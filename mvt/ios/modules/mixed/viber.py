# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 Claudio Guarnieri.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging
import sqlite3
from base64 import b64encode
from typing import Optional, Union

from mvt.common.utils import check_for_links, convert_mactime_to_iso

from ..base import IOSExtraction

VIBER_BACKUP_IDS = [
    "83b9310399a905c7781f95580174f321cd18fd97e",
]
VIBER_ROOT_PATHS = [
    "private/var/mobile/Containers/Shared/AppGroup/*/com.viber/database/viber-database.sqlite",
]

class Viber(IOSExtraction):
    """This module extracts all Viber messages containing links."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        target_path: Optional[str] = None,
        results_path: Optional[str] = None,
        module_options: Optional[dict] = None,
        log: logging.Logger = logging.getLogger(__name__),
        results: Optional[list] = None,
    ) -> None:
        super().__init__(
            file_path=file_path,
            target_path=target_path,
            results_path=results_path,
            module_options=module_options,
            log=log,
            results=results,
        )


    def serialize(self, record: dict) -> Union[dict, list]:
        text = record.get("ZTEXT", "").replace("\n", "\\n")
        links_text = ""
        if record.get("links"):
            links_text = " - Embedded links: " + ", ".join(record["links"])

        return {
            "timestamp": record.get("isodate"),
            "module": self.__class__.__name__,
            "event": "message",
            "data": f"'{text}' from {record.get('ZPHONE', 'Unknown')}{links_text}",
        }

    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            ioc = self.indicators.check_domains(result.get("links", []))
            if ioc:
                result["matched_indicator"] = ioc
                self.detected.append(result)

    def run(self) -> None:
        self._find_ios_database(
            backup_ids=VIBER_BACKUP_IDS, root_paths=VIBER_ROOT_PATHS
        )
        self.log.info("Found Viber database at path: %s", self.file_path)
        try:

            conn = sqlite3.connect(self.file_path)
            cur = conn.cursor()

            # Query all messages while retrieving related data from the Viber messages and phone numbers
            cur.execute(
            """
                SELECT *,
                  ZPHONENUMBER.ZPHONE
                FROM ZVIBERMESSAGE,ZPHONENUMBER 
                WHERE ZVIBERMESSAGE.ZPHONENUMINDEX = ZPHONENUMBER.Z_PK;
            """
            )
        except sqlite3.DatabaseError as exc:
            conn.close()
            if "database disk image is malformed" in str(exc):
                self._recover_sqlite_db_if_needed(self.file_path, forced=True)
                conn = sqlite3.connect(self.file_path)
                cur = conn.cursor()
                cur.execute(
                """
                  SELECT *,
                    ZPHONENUMBER.ZPHONE
                  FROM ZVIBERMESSAGE,ZPHONENUMBER 
                  WHERE ZVIBERMESSAGE.ZPHONENUMINDEX = ZPHONENUMBER.Z_PK;
                  """
                )
            else:
                raise exc                        
        names = [description[0] for description in cur.description]

        for message_row in cur:
            message = {}
            for index, value in enumerate(message_row):
                message[names[index]] = value

            message["isodate"] = convert_mactime_to_iso(message.get("ZMESSAGEDATE"))
            message["ZTEXT"] = message["ZTEXT"] if message["ZTEXT"] else ""

            # Extract links from the Viber message. URLs can be stored in
            # multiple fields/columns.
            # Check each of them!
            message_links = []
            fields_with_links = [
                "ZTEXT",
                "ZCLIENTMETADATA",
            ]
            for field in fields_with_links:
                if message.get(field):
                    message_links.extend(check_for_links(message.get(field, "")))

            # Remove Viber internal media URLs.
            filtered_links = []
            for link in message_links:
                if not (
                    link.startswith("viber://")
                    or link.startswith("https://chatapi.viber.com/")
                ):
                    filtered_links.append(link)

            # Add all the links found to the record
            if filtered_links or (message.get("ZTEXT") or "").strip() == "":
                message["links"] = list(set(filtered_links))
            self.results.append(message)

        cur.close()
        conn.close()

        self.log.info("Extracted a total of %d Viber messages", len(self.results))
