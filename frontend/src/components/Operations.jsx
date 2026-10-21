import Guard from "./Guard.jsx";
import CapturePanel from "./CapturePanel.jsx";
import FilesPanel from "./FilesPanel.jsx";
import IngestPanel from "./IngestPanel.jsx";
import LogsPanel from "./LogsPanel.jsx";
import ModelPanel from "./ModelPanel.jsx";
import NotificationSettings from "./NotificationSettings.jsx";
import ProxyPanel from "./ProxyPanel.jsx";
import ServerPanel from "./ServerPanel.jsx";
import UsersPanel from "./UsersPanel.jsx";

/** Everything an admin would otherwise do in a terminal. */
export default function Operations({ live }) {
  return (
    <div className="ops">
      <div className="ops-col">
        <Guard name="ModelPanel"><ModelPanel revision={live.revision} /></Guard>
        <Guard name="FilesPanel"><FilesPanel revision={live.revision} /></Guard>
        <Guard name="LogsPanel"><LogsPanel revision={live.revision} /></Guard>
      </div>

      <div className="ops-col">
        <Guard name="CapturePanel"><CapturePanel status={live.capture} /></Guard>
        <Guard name="IngestPanel"><IngestPanel revision={live.revision} /></Guard>
        <Guard name="ProxyPanel"><ProxyPanel /></Guard>
        <Guard name="NotificationSettings"><NotificationSettings /></Guard>
        <Guard name="ServerPanel"><ServerPanel /></Guard>
        <Guard name="UsersPanel"><UsersPanel /></Guard>
      </div>
    </div>
  );
}
