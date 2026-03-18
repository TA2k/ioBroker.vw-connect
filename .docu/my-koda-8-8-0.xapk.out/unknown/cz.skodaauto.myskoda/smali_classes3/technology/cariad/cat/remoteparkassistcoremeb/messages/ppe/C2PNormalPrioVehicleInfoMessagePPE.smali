.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000p\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008)\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008;\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 \u009a\u00012\u00020\u0001:\u0002\u009a\u0001B\u0083\u0003\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0005\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\r\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0010\u0012\u0008\u0008\u0002\u0010\u0011\u001a\u00020\u0010\u0012\u0008\u0008\u0002\u0010\u0012\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0013\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0015\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0016\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0017\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0018\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0019\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u001b\u0012\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u001b\u0012\u0008\u0008\u0002\u0010\u001d\u001a\u00020\u001b\u0012\u0008\u0008\u0002\u0010\u001e\u001a\u00020\u001b\u0012\u0008\u0008\u0002\u0010\u001f\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010 \u001a\u00020\t\u0012\u0008\u0008\u0002\u0010!\u001a\u00020\"\u0012\u0008\u0008\u0002\u0010#\u001a\u00020\"\u0012\u0008\u0008\u0002\u0010$\u001a\u00020%\u0012\u0008\u0008\u0002\u0010&\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\'\u001a\u00020(\u0012\u0008\u0008\u0002\u0010)\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010*\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010+\u001a\u00020,\u0012\u0008\u0008\u0002\u0010-\u001a\u00020,\u0012\u0008\u0008\u0002\u0010.\u001a\u00020,\u0012\u0008\u0008\u0002\u0010/\u001a\u00020,\u0012\u0008\u0008\u0002\u00100\u001a\u00020,\u00a2\u0006\u0004\u00081\u00102J\u0008\u0010Y\u001a\u00020ZH\u0016J\t\u0010m\u001a\u00020\u0003H\u00c6\u0003J\t\u0010n\u001a\u00020\u0005H\u00c6\u0003J\t\u0010o\u001a\u00020\u0005H\u00c6\u0003J\t\u0010p\u001a\u00020\u0003H\u00c6\u0003J\t\u0010q\u001a\u00020\tH\u00c6\u0003J\t\u0010r\u001a\u00020\tH\u00c6\u0003J\t\u0010s\u001a\u00020\u0003H\u00c6\u0003J\t\u0010t\u001a\u00020\u0003H\u00c6\u0003J\t\u0010u\u001a\u00020\u0003H\u00c6\u0003J\t\u0010v\u001a\u00020\u0003H\u00c6\u0003J\t\u0010w\u001a\u00020\u0010H\u00c6\u0003J\t\u0010x\u001a\u00020\u0010H\u00c6\u0003J\t\u0010y\u001a\u00020\tH\u00c6\u0003J\t\u0010z\u001a\u00020\tH\u00c6\u0003J\t\u0010{\u001a\u00020\tH\u00c6\u0003J\t\u0010|\u001a\u00020\tH\u00c6\u0003J\t\u0010}\u001a\u00020\tH\u00c6\u0003J\t\u0010~\u001a\u00020\tH\u00c6\u0003J\t\u0010\u007f\u001a\u00020\tH\u00c6\u0003J\n\u0010\u0080\u0001\u001a\u00020\tH\u00c6\u0003J\n\u0010\u0081\u0001\u001a\u00020\u001bH\u00c6\u0003J\n\u0010\u0082\u0001\u001a\u00020\u001bH\u00c6\u0003J\n\u0010\u0083\u0001\u001a\u00020\u001bH\u00c6\u0003J\n\u0010\u0084\u0001\u001a\u00020\u001bH\u00c6\u0003J\n\u0010\u0085\u0001\u001a\u00020\tH\u00c6\u0003J\n\u0010\u0086\u0001\u001a\u00020\tH\u00c6\u0003J\n\u0010\u0087\u0001\u001a\u00020\"H\u00c6\u0003J\n\u0010\u0088\u0001\u001a\u00020\"H\u00c6\u0003J\n\u0010\u0089\u0001\u001a\u00020%H\u00c6\u0003J\n\u0010\u008a\u0001\u001a\u00020\tH\u00c6\u0003J\n\u0010\u008b\u0001\u001a\u00020(H\u00c6\u0003J\n\u0010\u008c\u0001\u001a\u00020\tH\u00c6\u0003J\n\u0010\u008d\u0001\u001a\u00020\tH\u00c6\u0003J\n\u0010\u008e\u0001\u001a\u00020,H\u00c6\u0003J\n\u0010\u008f\u0001\u001a\u00020,H\u00c6\u0003J\n\u0010\u0090\u0001\u001a\u00020,H\u00c6\u0003J\n\u0010\u0091\u0001\u001a\u00020,H\u00c6\u0003J\n\u0010\u0092\u0001\u001a\u00020,H\u00c6\u0003J\u0086\u0003\u0010\u0093\u0001\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\t2\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u00032\u0008\u0008\u0002\u0010\r\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u00102\u0008\u0008\u0002\u0010\u0011\u001a\u00020\u00102\u0008\u0008\u0002\u0010\u0012\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0013\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0014\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0015\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0016\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0017\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0018\u001a\u00020\t2\u0008\u0008\u0002\u0010\u0019\u001a\u00020\t2\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u001b2\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u001b2\u0008\u0008\u0002\u0010\u001d\u001a\u00020\u001b2\u0008\u0008\u0002\u0010\u001e\u001a\u00020\u001b2\u0008\u0008\u0002\u0010\u001f\u001a\u00020\t2\u0008\u0008\u0002\u0010 \u001a\u00020\t2\u0008\u0008\u0002\u0010!\u001a\u00020\"2\u0008\u0008\u0002\u0010#\u001a\u00020\"2\u0008\u0008\u0002\u0010$\u001a\u00020%2\u0008\u0008\u0002\u0010&\u001a\u00020\t2\u0008\u0008\u0002\u0010\'\u001a\u00020(2\u0008\u0008\u0002\u0010)\u001a\u00020\t2\u0008\u0008\u0002\u0010*\u001a\u00020\t2\u0008\u0008\u0002\u0010+\u001a\u00020,2\u0008\u0008\u0002\u0010-\u001a\u00020,2\u0008\u0008\u0002\u0010.\u001a\u00020,2\u0008\u0008\u0002\u0010/\u001a\u00020,2\u0008\u0008\u0002\u00100\u001a\u00020,H\u00c6\u0001J\u0016\u0010\u0094\u0001\u001a\u00020\t2\n\u0010\u0095\u0001\u001a\u0005\u0018\u00010\u0096\u0001H\u00d6\u0003J\n\u0010\u0097\u0001\u001a\u00020,H\u00d6\u0001J\u000b\u0010\u0098\u0001\u001a\u00030\u0099\u0001H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00083\u00104R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00085\u00106R\u0011\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00087\u00106R\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00088\u00104R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00089\u0010:R\u0011\u0010\n\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008;\u0010:R\u0011\u0010\u000b\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008<\u00104R\u0011\u0010\u000c\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008=\u00104R\u0011\u0010\r\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008>\u00104R\u0011\u0010\u000e\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008?\u00104R\u0011\u0010\u000f\u001a\u00020\u0010\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008@\u0010AR\u0011\u0010\u0011\u001a\u00020\u0010\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008B\u0010AR\u0011\u0010\u0012\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0012\u0010:R\u0011\u0010\u0013\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010:R\u0011\u0010\u0014\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010:R\u0011\u0010\u0015\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010:R\u0011\u0010\u0016\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0016\u0010:R\u0011\u0010\u0017\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0017\u0010:R\u0011\u0010\u0018\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0018\u0010:R\u0011\u0010\u0019\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0019\u0010:R\u0011\u0010\u001a\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008C\u0010DR\u0011\u0010\u001c\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008E\u0010DR\u0011\u0010\u001d\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008F\u0010DR\u0011\u0010\u001e\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008G\u0010DR\u0011\u0010\u001f\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001f\u0010:R\u0011\u0010 \u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008 \u0010:R\u0011\u0010!\u001a\u00020\"\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008H\u0010IR\u0011\u0010#\u001a\u00020\"\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008J\u0010IR\u0011\u0010$\u001a\u00020%\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008K\u0010LR\u0011\u0010&\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008&\u0010:R\u0011\u0010\'\u001a\u00020(\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008M\u0010NR\u0011\u0010)\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008)\u0010:R\u0011\u0010*\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008*\u0010:R\u0011\u0010+\u001a\u00020,\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008O\u0010PR\u0011\u0010-\u001a\u00020,\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008Q\u0010PR\u0011\u0010.\u001a\u00020,\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008R\u0010PR\u0011\u0010/\u001a\u00020,\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008S\u0010PR\u0011\u00100\u001a\u00020,\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008T\u0010PR\u0014\u0010U\u001a\u00020VX\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008W\u0010XR\u0014\u0010[\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\\\u0010:R\u0014\u0010]\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008^\u0010:R\u0014\u0010_\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008`\u0010:R\u0014\u0010a\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008b\u0010:R\u0014\u0010c\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008d\u0010:R\u0014\u0010e\u001a\u00020\t8BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008f\u0010:R\u0014\u0010g\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008h\u0010:R\u0014\u0010i\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008j\u0010:R\u0014\u0010k\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008l\u0010:\u00a8\u0006\u009b\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "sunroofOpeningPercentage",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "sunroofMode",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;",
        "sunroofCapMode",
        "sunroofCapOpeningPercentage",
        "sunroofAvailable",
        "",
        "sunroofCapAvailable",
        "windowStatusPassengerSideFront",
        "windowStatusDriverSideFront",
        "windowStatusPassengerSideRear",
        "windowStatusDriverSideRear",
        "centralLockingInternalStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;",
        "centralLockingExternalStatus",
        "isDoorLockedDriverSideFront",
        "isDoorLockedPassengerSideFront",
        "isDoorLockedDriverSideRear",
        "isDoorLockedPassengerSideRear",
        "isDoorAlarmActivatedDriverSideFront",
        "isDoorAlarmActivatedPassengerSideFront",
        "isDoorAlarmActivatedDriverSideRear",
        "isDoorAlarmActivatedPassengerSideRear",
        "doorOpenDriverSideFrontStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;",
        "doorOpenPassengerSideFrontStatus",
        "doorOpenDriverSideRearStatus",
        "doorOpenPassengerSideRearStatus",
        "isTrunkOpen",
        "isHoodOpen",
        "hvlmAcceptItSystemPeRange",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;",
        "acPlugUnlocking",
        "engineType",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;",
        "isBackAxleControlAvailable",
        "wheelBase",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;",
        "isGarageDoorOpenerAvailable",
        "isComfortClosingPossible",
        "vehicleLength",
        "",
        "vehicleWidth",
        "vehicleWheelbase",
        "vehicleFrontOverhang",
        "vehicleRearOverhang",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIII)V",
        "getSunroofOpeningPercentage",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "getSunroofMode",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;",
        "getSunroofCapMode",
        "getSunroofCapOpeningPercentage",
        "getSunroofAvailable",
        "()Z",
        "getSunroofCapAvailable",
        "getWindowStatusPassengerSideFront",
        "getWindowStatusDriverSideFront",
        "getWindowStatusPassengerSideRear",
        "getWindowStatusDriverSideRear",
        "getCentralLockingInternalStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;",
        "getCentralLockingExternalStatus",
        "getDoorOpenDriverSideFrontStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;",
        "getDoorOpenPassengerSideFrontStatus",
        "getDoorOpenDriverSideRearStatus",
        "getDoorOpenPassengerSideRearStatus",
        "getHvlmAcceptItSystemPeRange",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;",
        "getAcPlugUnlocking",
        "getEngineType",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;",
        "getWheelBase",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;",
        "getVehicleLength",
        "()I",
        "getVehicleWidth",
        "getVehicleWheelbase",
        "getVehicleFrontOverhang",
        "getVehicleRearOverhang",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "hasOpenWindows",
        "getHasOpenWindows$remoteparkassistcoremeb_release",
        "hasOpenDoorsOrFlaps",
        "getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release",
        "isHavingDoorsError",
        "isHavingDoorsError$remoteparkassistcoremeb_release",
        "isVehicleLocked",
        "isVehicleLocked$remoteparkassistcoremeb_release",
        "isSafeLockActive",
        "isSafeLockActive$remoteparkassistcoremeb_release",
        "centralLockingActive",
        "getCentralLockingActive",
        "isSunroofOpen",
        "isSunroofOpen$remoteparkassistcoremeb_release",
        "isSunroofAvailable",
        "isSunroofAvailable$remoteparkassistcoremeb_release",
        "isElectricalVehicle",
        "isElectricalVehicle$remoteparkassistcoremeb_release",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "component8",
        "component9",
        "component10",
        "component11",
        "component12",
        "component13",
        "component14",
        "component15",
        "component16",
        "component17",
        "component18",
        "component19",
        "component20",
        "component21",
        "component22",
        "component23",
        "component24",
        "component25",
        "component26",
        "component27",
        "component28",
        "component29",
        "component30",
        "component31",
        "component32",
        "component33",
        "component34",
        "component35",
        "component36",
        "component37",
        "component38",
        "copy",
        "equals",
        "other",
        "",
        "hashCode",
        "toString",
        "",
        "Companion",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;

.field private static final GwSm_SM_BT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_BT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_BT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_BT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_EngineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_FT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_FT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_FT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_FT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_GarageDoorOpener_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HAL_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HBFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HBFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HBFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HBFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HVLMAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_HVLMAutounlockAc:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_MD1_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_MD1_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_MD1_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_SAD2_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_SAD2_Deckel_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_SAD2_Deckel_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_Vehicle_Dim_Length:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_Vehicle_Dim_Overhang_Front:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_Vehicle_Dim_Overhang_Rear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_Vehicle_Dim_Wheelbase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_Vehicle_Dim_Width:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_WheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_WinClPossible:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_ZV_Frontdeckel_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_ZV_Heck_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_ZV_verriegelt_extern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final GwSm_SM_ZV_verriegelt_intern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

.field private final centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

.field private final centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

.field private final doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

.field private final doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

.field private final doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

.field private final engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

.field private final hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

.field private final isBackAxleControlAvailable:Z

.field private final isComfortClosingPossible:Z

.field private final isDoorAlarmActivatedDriverSideFront:Z

.field private final isDoorAlarmActivatedDriverSideRear:Z

.field private final isDoorAlarmActivatedPassengerSideFront:Z

.field private final isDoorAlarmActivatedPassengerSideRear:Z

.field private final isDoorLockedDriverSideFront:Z

.field private final isDoorLockedDriverSideRear:Z

.field private final isDoorLockedPassengerSideFront:Z

.field private final isDoorLockedPassengerSideRear:Z

.field private final isGarageDoorOpenerAvailable:Z

.field private final isHoodOpen:Z

.field private final isTrunkOpen:Z

.field private final sunroofAvailable:Z

.field private final sunroofCapAvailable:Z

.field private final sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

.field private final sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

.field private final sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final vehicleFrontOverhang:I

.field private final vehicleLength:I

.field private final vehicleRearOverhang:I

.field private final vehicleWheelbase:I

.field private final vehicleWidth:I

.field private final wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

.field private final windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x24

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250400401000000L    # 3.2326131902012995E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->address:J

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->priority:B

    .line 22
    .line 23
    const/16 v1, 0x15

    .line 24
    .line 25
    sput v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->byteLength:I

    .line 26
    .line 27
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x7

    .line 31
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 35
    .line 36
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 37
    .line 38
    const/4 v2, 0x1

    .line 39
    invoke-direct {v1, v3, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    const/16 v4, 0x8

    .line 47
    .line 48
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 49
    .line 50
    .line 51
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Deckel_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 52
    .line 53
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 54
    .line 55
    const/16 v5, 0x9

    .line 56
    .line 57
    invoke-direct {v1, v5, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 58
    .line 59
    .line 60
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Deckel_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 61
    .line 62
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 63
    .line 64
    const/16 v3, 0x10

    .line 65
    .line 66
    invoke-direct {v1, v3, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 67
    .line 68
    .line 69
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 70
    .line 71
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 72
    .line 73
    const/16 v5, 0x11

    .line 74
    .line 75
    invoke-direct {v1, v5, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 76
    .line 77
    .line 78
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 79
    .line 80
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    const/16 v5, 0x12

    .line 83
    .line 84
    invoke-direct {v1, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 85
    .line 86
    .line 87
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 88
    .line 89
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 90
    .line 91
    const/16 v5, 0x1a

    .line 92
    .line 93
    invoke-direct {v1, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 94
    .line 95
    .line 96
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 97
    .line 98
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 99
    .line 100
    const/16 v5, 0x22

    .line 101
    .line 102
    invoke-direct {v1, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 103
    .line 104
    .line 105
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 106
    .line 107
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 108
    .line 109
    const/16 v5, 0x2a

    .line 110
    .line 111
    invoke-direct {v1, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 112
    .line 113
    .line 114
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 115
    .line 116
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 117
    .line 118
    const/16 v4, 0x32

    .line 119
    .line 120
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 121
    .line 122
    .line 123
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_verriegelt_intern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 124
    .line 125
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 126
    .line 127
    const/16 v4, 0x34

    .line 128
    .line 129
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 130
    .line 131
    .line 132
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_verriegelt_extern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 133
    .line 134
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 135
    .line 136
    const/16 v4, 0x36

    .line 137
    .line 138
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 139
    .line 140
    .line 141
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 142
    .line 143
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 144
    .line 145
    const/16 v4, 0x37

    .line 146
    .line 147
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 148
    .line 149
    .line 150
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 151
    .line 152
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 153
    .line 154
    const/16 v4, 0x38

    .line 155
    .line 156
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 157
    .line 158
    .line 159
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 160
    .line 161
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 162
    .line 163
    const/16 v4, 0x39

    .line 164
    .line 165
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 166
    .line 167
    .line 168
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 169
    .line 170
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 171
    .line 172
    const/16 v4, 0x3a

    .line 173
    .line 174
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 175
    .line 176
    .line 177
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 178
    .line 179
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 180
    .line 181
    const/16 v4, 0x3b

    .line 182
    .line 183
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 184
    .line 185
    .line 186
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 187
    .line 188
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 189
    .line 190
    const/16 v4, 0x3c

    .line 191
    .line 192
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 193
    .line 194
    .line 195
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 196
    .line 197
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 198
    .line 199
    const/16 v4, 0x3d

    .line 200
    .line 201
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 202
    .line 203
    .line 204
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 205
    .line 206
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 207
    .line 208
    const/16 v4, 0x3e

    .line 209
    .line 210
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 211
    .line 212
    .line 213
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 214
    .line 215
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 216
    .line 217
    const/16 v4, 0x40

    .line 218
    .line 219
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 220
    .line 221
    .line 222
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 223
    .line 224
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 225
    .line 226
    const/16 v4, 0x42

    .line 227
    .line 228
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 229
    .line 230
    .line 231
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 232
    .line 233
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 234
    .line 235
    const/16 v4, 0x44

    .line 236
    .line 237
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 238
    .line 239
    .line 240
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 241
    .line 242
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 243
    .line 244
    const/16 v4, 0x46

    .line 245
    .line 246
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 247
    .line 248
    .line 249
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_Heck_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 250
    .line 251
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 252
    .line 253
    const/16 v4, 0x47

    .line 254
    .line 255
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 256
    .line 257
    .line 258
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_Frontdeckel_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 259
    .line 260
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 261
    .line 262
    const/16 v4, 0x48

    .line 263
    .line 264
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 265
    .line 266
    .line 267
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HVLMAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 268
    .line 269
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 270
    .line 271
    const/16 v4, 0x4a

    .line 272
    .line 273
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 274
    .line 275
    .line 276
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HVLMAutounlockAc:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 277
    .line 278
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 279
    .line 280
    const/16 v4, 0x4c

    .line 281
    .line 282
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 283
    .line 284
    .line 285
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_EngineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 286
    .line 287
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 288
    .line 289
    const/16 v1, 0x4e

    .line 290
    .line 291
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 292
    .line 293
    .line 294
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HAL_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 295
    .line 296
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 297
    .line 298
    const/16 v1, 0x4f

    .line 299
    .line 300
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 301
    .line 302
    .line 303
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_WheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 304
    .line 305
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 306
    .line 307
    const/16 v1, 0x50

    .line 308
    .line 309
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 310
    .line 311
    .line 312
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_GarageDoorOpener_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 313
    .line 314
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 315
    .line 316
    const/16 v1, 0x51

    .line 317
    .line 318
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 319
    .line 320
    .line 321
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_WinClPossible:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 322
    .line 323
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 324
    .line 325
    const/16 v1, 0x52

    .line 326
    .line 327
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 328
    .line 329
    .line 330
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Length:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 331
    .line 332
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 333
    .line 334
    const/16 v1, 0x62

    .line 335
    .line 336
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 337
    .line 338
    .line 339
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Width:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 340
    .line 341
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 342
    .line 343
    const/16 v1, 0x72

    .line 344
    .line 345
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 346
    .line 347
    .line 348
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Wheelbase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 349
    .line 350
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 351
    .line 352
    const/16 v1, 0x82

    .line 353
    .line 354
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 355
    .line 356
    .line 357
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Overhang_Front:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 358
    .line 359
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 360
    .line 361
    const/16 v1, 0x92

    .line 362
    .line 363
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 364
    .line 365
    .line 366
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Overhang_Rear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 367
    .line 368
    return-void
.end method

.method public constructor <init>()V
    .locals 42

    .line 1
    const/16 v40, 0x3f

    const/16 v41, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, -0x1

    move-object/from16 v0, p0

    invoke-direct/range {v0 .. v41}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIIIIILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIII)V
    .locals 16

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    move-object/from16 v4, p4

    move-object/from16 v5, p7

    move-object/from16 v6, p8

    move-object/from16 v7, p9

    move-object/from16 v8, p10

    move-object/from16 v9, p11

    move-object/from16 v10, p12

    move-object/from16 v11, p21

    move-object/from16 v12, p22

    move-object/from16 v13, p23

    move-object/from16 v14, p24

    move-object/from16 v15, p27

    const-string v0, "sunroofOpeningPercentage"

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofMode"

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofCapMode"

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofCapOpeningPercentage"

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideFront"

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideFront"

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideRear"

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideRear"

    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "centralLockingInternalStatus"

    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "centralLockingExternalStatus"

    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenDriverSideFrontStatus"

    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenPassengerSideFrontStatus"

    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenDriverSideRearStatus"

    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenPassengerSideRearStatus"

    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "hvlmAcceptItSystemPeRange"

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "acPlugUnlocking"

    move-object/from16 v15, p28

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "engineType"

    move-object/from16 v15, p29

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "wheelBase"

    move-object/from16 v15, p31

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct/range {p0 .. p0}, Ljava/lang/Object;-><init>()V

    move-object/from16 v0, p0

    .line 3
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 4
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 5
    iput-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 6
    iput-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    move/from16 v1, p5

    .line 7
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    move/from16 v1, p6

    .line 8
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 9
    iput-object v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 10
    iput-object v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 11
    iput-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 12
    iput-object v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 13
    iput-object v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 14
    iput-object v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    move/from16 v1, p13

    .line 15
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    move/from16 v1, p14

    .line 16
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    move/from16 v1, p15

    .line 17
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    move/from16 v1, p16

    .line 18
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    move/from16 v1, p17

    .line 19
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    move/from16 v1, p18

    .line 20
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    move/from16 v1, p19

    .line 21
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    move/from16 v1, p20

    .line 22
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 23
    iput-object v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 24
    iput-object v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 25
    iput-object v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 26
    iput-object v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    move/from16 v1, p25

    .line 27
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    move/from16 v1, p26

    .line 28
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    move-object/from16 v1, p27

    .line 29
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    move-object/from16 v1, p28

    .line 30
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    move-object/from16 v1, p29

    .line 31
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    move/from16 v1, p30

    .line 32
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 33
    iput-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    move/from16 v1, p32

    .line 34
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    move/from16 v1, p33

    .line 35
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    move/from16 v1, p34

    .line 36
    iput v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    move/from16 v1, p35

    .line 37
    iput v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    move/from16 v1, p36

    .line 38
    iput v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    move/from16 v1, p37

    .line 39
    iput v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    move/from16 v1, p38

    .line 40
    iput v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 41
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;

    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIIIIILkotlin/jvm/internal/g;)V
    .locals 38

    move/from16 v0, p39

    and-int/lit8 v1, v0, 0x1

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_0

    .line 42
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v1, v3, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_0

    :cond_0
    move-object/from16 v1, p1

    :goto_0
    and-int/lit8 v5, v0, 0x2

    if-eqz v5, :cond_1

    .line 43
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;->Tilting:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    goto :goto_1

    :cond_1
    move-object/from16 v5, p2

    :goto_1
    and-int/lit8 v6, v0, 0x4

    if-eqz v6, :cond_2

    .line 44
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;->Tilting:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    goto :goto_2

    :cond_2
    move-object/from16 v6, p3

    :goto_2
    and-int/lit8 v7, v0, 0x8

    if-eqz v7, :cond_3

    .line 45
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v7, v3, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_3

    :cond_3
    move-object/from16 v7, p4

    :goto_3
    and-int/lit8 v8, v0, 0x10

    if-eqz v8, :cond_4

    move v8, v3

    goto :goto_4

    :cond_4
    move/from16 v8, p5

    :goto_4
    and-int/lit8 v9, v0, 0x20

    if-eqz v9, :cond_5

    move v9, v3

    goto :goto_5

    :cond_5
    move/from16 v9, p6

    :goto_5
    and-int/lit8 v10, v0, 0x40

    if-eqz v10, :cond_6

    .line 46
    new-instance v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v10, v3, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_6

    :cond_6
    move-object/from16 v10, p7

    :goto_6
    and-int/lit16 v11, v0, 0x80

    if-eqz v11, :cond_7

    .line 47
    new-instance v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v11, v3, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_7

    :cond_7
    move-object/from16 v11, p8

    :goto_7
    and-int/lit16 v12, v0, 0x100

    if-eqz v12, :cond_8

    .line 48
    new-instance v12, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v12, v3, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_8

    :cond_8
    move-object/from16 v12, p9

    :goto_8
    and-int/lit16 v13, v0, 0x200

    if-eqz v13, :cond_9

    .line 49
    new-instance v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v13, v3, v4, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_9

    :cond_9
    move-object/from16 v13, p10

    :goto_9
    and-int/lit16 v2, v0, 0x400

    if-eqz v2, :cond_a

    .line 50
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    goto :goto_a

    :cond_a
    move-object/from16 v2, p11

    :goto_a
    and-int/lit16 v4, v0, 0x800

    if-eqz v4, :cond_b

    .line 51
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    goto :goto_b

    :cond_b
    move-object/from16 v4, p12

    :goto_b
    and-int/lit16 v14, v0, 0x1000

    if-eqz v14, :cond_c

    move v14, v3

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v0, 0x2000

    if-eqz v15, :cond_d

    move v15, v3

    goto :goto_d

    :cond_d
    move/from16 v15, p14

    :goto_d
    and-int/lit16 v3, v0, 0x4000

    if-eqz v3, :cond_e

    const/4 v3, 0x0

    goto :goto_e

    :cond_e
    move/from16 v3, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v0, v16

    if-eqz v16, :cond_f

    const/16 v16, 0x0

    goto :goto_f

    :cond_f
    move/from16 v16, p16

    :goto_f
    const/high16 v17, 0x10000

    and-int v17, v0, v17

    if-eqz v17, :cond_10

    const/16 v17, 0x0

    goto :goto_10

    :cond_10
    move/from16 v17, p17

    :goto_10
    const/high16 v18, 0x20000

    and-int v18, v0, v18

    if-eqz v18, :cond_11

    const/16 v18, 0x0

    goto :goto_11

    :cond_11
    move/from16 v18, p18

    :goto_11
    const/high16 v19, 0x40000

    and-int v19, v0, v19

    if-eqz v19, :cond_12

    const/16 v19, 0x0

    goto :goto_12

    :cond_12
    move/from16 v19, p19

    :goto_12
    const/high16 v20, 0x80000

    and-int v20, v0, v20

    if-eqz v20, :cond_13

    const/16 v20, 0x0

    goto :goto_13

    :cond_13
    move/from16 v20, p20

    :goto_13
    const/high16 v21, 0x100000

    and-int v21, v0, v21

    if-eqz v21, :cond_14

    .line 52
    sget-object v21, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_14

    :cond_14
    move-object/from16 v21, p21

    :goto_14
    const/high16 v22, 0x200000

    and-int v22, v0, v22

    if-eqz v22, :cond_15

    .line 53
    sget-object v22, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_15

    :cond_15
    move-object/from16 v22, p22

    :goto_15
    const/high16 v23, 0x400000

    and-int v23, v0, v23

    if-eqz v23, :cond_16

    .line 54
    sget-object v23, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_16

    :cond_16
    move-object/from16 v23, p23

    :goto_16
    const/high16 v24, 0x800000

    and-int v24, v0, v24

    if-eqz v24, :cond_17

    .line 55
    sget-object v24, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_17

    :cond_17
    move-object/from16 v24, p24

    :goto_17
    const/high16 v25, 0x1000000

    and-int v25, v0, v25

    if-eqz v25, :cond_18

    const/16 v25, 0x0

    goto :goto_18

    :cond_18
    move/from16 v25, p25

    :goto_18
    const/high16 v26, 0x2000000

    and-int v26, v0, v26

    if-eqz v26, :cond_19

    const/16 v26, 0x0

    goto :goto_19

    :cond_19
    move/from16 v26, p26

    :goto_19
    const/high16 v27, 0x4000000

    and-int v27, v0, v27

    if-eqz v27, :cond_1a

    .line 56
    sget-object v27, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;->INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    goto :goto_1a

    :cond_1a
    move-object/from16 v27, p27

    :goto_1a
    const/high16 v28, 0x8000000

    and-int v28, v0, v28

    if-eqz v28, :cond_1b

    .line 57
    sget-object v28, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;->INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    goto :goto_1b

    :cond_1b
    move-object/from16 v28, p28

    :goto_1b
    const/high16 v29, 0x10000000

    and-int v29, v0, v29

    if-eqz v29, :cond_1c

    .line 58
    sget-object v29, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;->COMBUSTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    goto :goto_1c

    :cond_1c
    move-object/from16 v29, p29

    :goto_1c
    const/high16 v30, 0x20000000

    and-int v30, v0, v30

    if-eqz v30, :cond_1d

    const/16 v30, 0x0

    goto :goto_1d

    :cond_1d
    move/from16 v30, p30

    :goto_1d
    const/high16 v31, 0x40000000    # 2.0f

    and-int v31, v0, v31

    if-eqz v31, :cond_1e

    .line 59
    sget-object v31, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;->NORMAL_WHEEL_BASE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    goto :goto_1e

    :cond_1e
    move-object/from16 v31, p31

    :goto_1e
    const/high16 v32, -0x80000000

    and-int v0, v0, v32

    if-eqz v0, :cond_1f

    const/4 v0, 0x0

    goto :goto_1f

    :cond_1f
    move/from16 v0, p32

    :goto_1f
    and-int/lit8 v32, p40, 0x1

    if-eqz v32, :cond_20

    const/16 v32, 0x0

    goto :goto_20

    :cond_20
    move/from16 v32, p33

    :goto_20
    and-int/lit8 v33, p40, 0x2

    if-eqz v33, :cond_21

    const/16 v33, 0x0

    goto :goto_21

    :cond_21
    move/from16 v33, p34

    :goto_21
    and-int/lit8 v34, p40, 0x4

    if-eqz v34, :cond_22

    const/16 v34, 0x0

    goto :goto_22

    :cond_22
    move/from16 v34, p35

    :goto_22
    and-int/lit8 v35, p40, 0x8

    if-eqz v35, :cond_23

    const/16 v35, 0x0

    goto :goto_23

    :cond_23
    move/from16 v35, p36

    :goto_23
    and-int/lit8 v36, p40, 0x10

    if-eqz v36, :cond_24

    const/16 v36, 0x0

    goto :goto_24

    :cond_24
    move/from16 v36, p37

    :goto_24
    and-int/lit8 v37, p40, 0x20

    if-eqz v37, :cond_25

    const/16 p39, 0x0

    :goto_25
    move-object/from16 p1, p0

    move/from16 p33, v0

    move-object/from16 p2, v1

    move-object/from16 p12, v2

    move/from16 p16, v3

    move-object/from16 p13, v4

    move-object/from16 p3, v5

    move-object/from16 p4, v6

    move-object/from16 p5, v7

    move/from16 p6, v8

    move/from16 p7, v9

    move-object/from16 p8, v10

    move-object/from16 p9, v11

    move-object/from16 p10, v12

    move-object/from16 p11, v13

    move/from16 p14, v14

    move/from16 p15, v15

    move/from16 p17, v16

    move/from16 p18, v17

    move/from16 p19, v18

    move/from16 p20, v19

    move/from16 p21, v20

    move-object/from16 p22, v21

    move-object/from16 p23, v22

    move-object/from16 p24, v23

    move-object/from16 p25, v24

    move/from16 p26, v25

    move/from16 p27, v26

    move-object/from16 p28, v27

    move-object/from16 p29, v28

    move-object/from16 p30, v29

    move/from16 p31, v30

    move-object/from16 p32, v31

    move/from16 p34, v32

    move/from16 p35, v33

    move/from16 p36, v34

    move/from16 p37, v35

    move/from16 p38, v36

    goto :goto_26

    :cond_25
    move/from16 p39, p38

    goto :goto_25

    .line 60
    :goto_26
    invoke-direct/range {p1 .. p39}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIII)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getGwSm_SM_BT_FH_Oeffnung$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_BT_Tuer_Status$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_BT_gesafet$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_BT_verriegelt$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_EngineType$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_EngineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_FT_FH_Oeffnung$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_FT_Tuer_Status$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_FT_gesafet$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_FT_verriegelt$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_GarageDoorOpener_Available$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_GarageDoorOpener_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HAL_Available$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HAL_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HBFS_FH_Oeffnung$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HBFS_Tuer_Status$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HBFS_gesafet$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HBFS_verriegelt$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HFS_FH_Oeffnung$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HFS_Tuer_Status$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HFS_gesafet$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HFS_verriegelt$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HVLMAcceptItSystemPeRange$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HVLMAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_HVLMAutounlockAc$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HVLMAutounlockAc:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_MD1_Available$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_MD1_Lage$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_MD1_Position$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_SAD2_Available$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_SAD2_Deckel_Lage$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Deckel_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_SAD2_Deckel_Position$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Deckel_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_Vehicle_Dim_Length$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Length:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_Vehicle_Dim_Overhang_Front$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Overhang_Front:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_Vehicle_Dim_Overhang_Rear$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Overhang_Rear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_Vehicle_Dim_Wheelbase$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Wheelbase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_Vehicle_Dim_Width$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_Vehicle_Dim_Width:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_WheelBase$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_WheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_WinClPossible$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_WinClPossible:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_ZV_Frontdeckel_offen$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_Frontdeckel_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_ZV_Heck_offen$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_Heck_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_ZV_verriegelt_extern_ist_02$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_verriegelt_extern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getGwSm_SM_ZV_verriegelt_intern_ist_02$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_verriegelt_intern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIIIIILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p39

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_0

    :cond_0
    move-object/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-object v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-boolean v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    goto :goto_4

    :cond_4
    move/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-boolean v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    goto :goto_5

    :cond_5
    move/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-object v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_6

    :cond_6
    move-object/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-object v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_7

    :cond_7
    move-object/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-object v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_8

    :cond_8
    move-object/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-object v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_9

    :cond_9
    move-object/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget-object v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    goto :goto_a

    :cond_a
    move-object/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-object v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    goto :goto_b

    :cond_b
    move-object/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget-boolean v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    goto :goto_d

    :cond_d
    move/from16 v15, p14

    :goto_d
    move-object/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-boolean v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    goto :goto_e

    :cond_e
    move/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    goto :goto_f

    :cond_f
    move/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p39, v16

    move/from16 p2, v1

    if-eqz v16, :cond_10

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    goto :goto_10

    :cond_10
    move/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p39, v16

    move/from16 p3, v1

    if-eqz v16, :cond_11

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    goto :goto_11

    :cond_11
    move/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p39, v16

    move/from16 p4, v1

    if-eqz v16, :cond_12

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    goto :goto_12

    :cond_12
    move/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p39, v16

    move/from16 p5, v1

    if-eqz v16, :cond_13

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    goto :goto_13

    :cond_13
    move/from16 v1, p20

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p39, v16

    move/from16 p6, v1

    if-eqz v16, :cond_14

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_14

    :cond_14
    move-object/from16 v1, p21

    :goto_14
    const/high16 v16, 0x200000

    and-int v16, p39, v16

    move-object/from16 p7, v1

    if-eqz v16, :cond_15

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_15

    :cond_15
    move-object/from16 v1, p22

    :goto_15
    const/high16 v16, 0x400000

    and-int v16, p39, v16

    move-object/from16 p8, v1

    if-eqz v16, :cond_16

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_16

    :cond_16
    move-object/from16 v1, p23

    :goto_16
    const/high16 v16, 0x800000

    and-int v16, p39, v16

    move-object/from16 p9, v1

    if-eqz v16, :cond_17

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    goto :goto_17

    :cond_17
    move-object/from16 v1, p24

    :goto_17
    const/high16 v16, 0x1000000

    and-int v16, p39, v16

    move-object/from16 p10, v1

    if-eqz v16, :cond_18

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    goto :goto_18

    :cond_18
    move/from16 v1, p25

    :goto_18
    const/high16 v16, 0x2000000

    and-int v16, p39, v16

    move/from16 p11, v1

    if-eqz v16, :cond_19

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    goto :goto_19

    :cond_19
    move/from16 v1, p26

    :goto_19
    const/high16 v16, 0x4000000

    and-int v16, p39, v16

    move/from16 p12, v1

    if-eqz v16, :cond_1a

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    goto :goto_1a

    :cond_1a
    move-object/from16 v1, p27

    :goto_1a
    const/high16 v16, 0x8000000

    and-int v16, p39, v16

    move-object/from16 p13, v1

    if-eqz v16, :cond_1b

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    goto :goto_1b

    :cond_1b
    move-object/from16 v1, p28

    :goto_1b
    const/high16 v16, 0x10000000

    and-int v16, p39, v16

    move-object/from16 p14, v1

    if-eqz v16, :cond_1c

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    goto :goto_1c

    :cond_1c
    move-object/from16 v1, p29

    :goto_1c
    const/high16 v16, 0x20000000

    and-int v16, p39, v16

    move-object/from16 p15, v1

    if-eqz v16, :cond_1d

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    goto :goto_1d

    :cond_1d
    move/from16 v1, p30

    :goto_1d
    const/high16 v16, 0x40000000    # 2.0f

    and-int v16, p39, v16

    move/from16 p16, v1

    if-eqz v16, :cond_1e

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    goto :goto_1e

    :cond_1e
    move-object/from16 v1, p31

    :goto_1e
    const/high16 v16, -0x80000000

    and-int v16, p39, v16

    move-object/from16 p17, v1

    if-eqz v16, :cond_1f

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    goto :goto_1f

    :cond_1f
    move/from16 v1, p32

    :goto_1f
    and-int/lit8 v16, p40, 0x1

    move/from16 p18, v1

    if-eqz v16, :cond_20

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    goto :goto_20

    :cond_20
    move/from16 v1, p33

    :goto_20
    and-int/lit8 v16, p40, 0x2

    move/from16 p19, v1

    if-eqz v16, :cond_21

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    goto :goto_21

    :cond_21
    move/from16 v1, p34

    :goto_21
    and-int/lit8 v16, p40, 0x4

    move/from16 p20, v1

    if-eqz v16, :cond_22

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    goto :goto_22

    :cond_22
    move/from16 v1, p35

    :goto_22
    and-int/lit8 v16, p40, 0x8

    move/from16 p21, v1

    if-eqz v16, :cond_23

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    goto :goto_23

    :cond_23
    move/from16 v1, p36

    :goto_23
    and-int/lit8 v16, p40, 0x10

    move/from16 p22, v1

    if-eqz v16, :cond_24

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    goto :goto_24

    :cond_24
    move/from16 v1, p37

    :goto_24
    and-int/lit8 v16, p40, 0x20

    if-eqz v16, :cond_25

    move/from16 p23, v1

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    move/from16 p38, p23

    move/from16 p39, v1

    move-object/from16 p24, p9

    move-object/from16 p25, p10

    move/from16 p26, p11

    move/from16 p27, p12

    move-object/from16 p28, p13

    move-object/from16 p29, p14

    move-object/from16 p30, p15

    move/from16 p31, p16

    move-object/from16 p32, p17

    move/from16 p33, p18

    move/from16 p34, p19

    move/from16 p35, p20

    move/from16 p36, p21

    move/from16 p37, p22

    move/from16 p16, v2

    move-object/from16 p9, v9

    move-object/from16 p10, v10

    move-object/from16 p11, v11

    move-object/from16 p12, v12

    move-object/from16 p13, v13

    move/from16 p14, v14

    move/from16 p15, v15

    move/from16 p17, p2

    move/from16 p18, p3

    move/from16 p19, p4

    move/from16 p20, p5

    move/from16 p21, p6

    move-object/from16 p22, p7

    move-object/from16 p23, p8

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move/from16 p6, v6

    move/from16 p7, v7

    move-object/from16 p8, v8

    :goto_25
    move-object/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_26

    :cond_25
    move/from16 p39, p38

    move/from16 p38, v1

    move-object/from16 p23, p8

    move-object/from16 p24, p9

    move-object/from16 p25, p10

    move/from16 p26, p11

    move/from16 p27, p12

    move-object/from16 p28, p13

    move-object/from16 p29, p14

    move-object/from16 p30, p15

    move/from16 p31, p16

    move-object/from16 p32, p17

    move/from16 p33, p18

    move/from16 p34, p19

    move/from16 p35, p20

    move/from16 p36, p21

    move/from16 p37, p22

    move/from16 p16, v2

    move-object/from16 p8, v8

    move-object/from16 p9, v9

    move-object/from16 p10, v10

    move-object/from16 p11, v11

    move-object/from16 p12, v12

    move-object/from16 p13, v13

    move/from16 p14, v14

    move/from16 p15, v15

    move/from16 p17, p2

    move/from16 p18, p3

    move/from16 p19, p4

    move/from16 p20, p5

    move/from16 p21, p6

    move-object/from16 p22, p7

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move/from16 p6, v6

    move/from16 p7, v7

    goto :goto_25

    :goto_26
    invoke-virtual/range {p1 .. p39}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIII)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    move-result-object v0

    return-object v0
.end method

.method private final getCentralLockingActive()Z
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;->VERRIEGELT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 8
    .line 9
    if-ne p0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component14()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component15()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component16()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component17()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component18()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component19()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component21()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component22()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component23()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component24()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component25()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component26()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component27()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component28()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component29()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component30()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component31()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component32()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component33()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component34()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    .line 2
    .line 3
    return p0
.end method

.method public final component35()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public final component36()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    .line 2
    .line 3
    return p0
.end method

.method public final component37()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    .line 2
    .line 3
    return p0
.end method

.method public final component38()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component6()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component7()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIII)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;
    .locals 40

    .line 1
    const-string v0, "sunroofOpeningPercentage"

    move-object/from16 v2, p1

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofMode"

    move-object/from16 v3, p2

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofCapMode"

    move-object/from16 v4, p3

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofCapOpeningPercentage"

    move-object/from16 v5, p4

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideFront"

    move-object/from16 v8, p7

    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideFront"

    move-object/from16 v9, p8

    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideRear"

    move-object/from16 v10, p9

    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideRear"

    move-object/from16 v11, p10

    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "centralLockingInternalStatus"

    move-object/from16 v12, p11

    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "centralLockingExternalStatus"

    move-object/from16 v13, p12

    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenDriverSideFrontStatus"

    move-object/from16 v1, p21

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenPassengerSideFrontStatus"

    move-object/from16 v6, p22

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenDriverSideRearStatus"

    move-object/from16 v7, p23

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "doorOpenPassengerSideRearStatus"

    move-object/from16 v14, p24

    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "hvlmAcceptItSystemPeRange"

    move-object/from16 v15, p27

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "acPlugUnlocking"

    move-object/from16 v1, p28

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "engineType"

    move-object/from16 v1, p29

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "wheelBase"

    move-object/from16 v1, p31

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    move/from16 v16, p15

    move/from16 v17, p16

    move/from16 v18, p17

    move/from16 v19, p18

    move/from16 v20, p19

    move/from16 v21, p20

    move-object/from16 v22, p21

    move/from16 v26, p25

    move/from16 v27, p26

    move-object/from16 v29, p28

    move-object/from16 v30, p29

    move/from16 v31, p30

    move-object/from16 v32, p31

    move/from16 v33, p32

    move/from16 v34, p33

    move/from16 v35, p34

    move/from16 v36, p35

    move/from16 v37, p36

    move/from16 v38, p37

    move/from16 v39, p38

    move-object/from16 v23, v6

    move-object/from16 v24, v7

    move-object/from16 v25, v14

    move-object/from16 v28, v15

    move/from16 v6, p5

    move/from16 v7, p6

    move/from16 v14, p13

    move/from16 v15, p14

    invoke-direct/range {v1 .. v39}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIII)V

    return-object v1
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 25
    .line 26
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 32
    .line 33
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 39
    .line 40
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 41
    .line 42
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 57
    .line 58
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 64
    .line 65
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 75
    .line 76
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 86
    .line 87
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 97
    .line 98
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 99
    .line 100
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 108
    .line 109
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 110
    .line 111
    if-eq v1, v3, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 115
    .line 116
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 117
    .line 118
    if-eq v1, v3, :cond_d

    .line 119
    .line 120
    return v2

    .line 121
    :cond_d
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 122
    .line 123
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 124
    .line 125
    if-eq v1, v3, :cond_e

    .line 126
    .line 127
    return v2

    .line 128
    :cond_e
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 129
    .line 130
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 131
    .line 132
    if-eq v1, v3, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 136
    .line 137
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 138
    .line 139
    if-eq v1, v3, :cond_10

    .line 140
    .line 141
    return v2

    .line 142
    :cond_10
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 143
    .line 144
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 145
    .line 146
    if-eq v1, v3, :cond_11

    .line 147
    .line 148
    return v2

    .line 149
    :cond_11
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 150
    .line 151
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 152
    .line 153
    if-eq v1, v3, :cond_12

    .line 154
    .line 155
    return v2

    .line 156
    :cond_12
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 157
    .line 158
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 159
    .line 160
    if-eq v1, v3, :cond_13

    .line 161
    .line 162
    return v2

    .line 163
    :cond_13
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 164
    .line 165
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 166
    .line 167
    if-eq v1, v3, :cond_14

    .line 168
    .line 169
    return v2

    .line 170
    :cond_14
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 171
    .line 172
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 173
    .line 174
    if-eq v1, v3, :cond_15

    .line 175
    .line 176
    return v2

    .line 177
    :cond_15
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 178
    .line 179
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 180
    .line 181
    if-eq v1, v3, :cond_16

    .line 182
    .line 183
    return v2

    .line 184
    :cond_16
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 185
    .line 186
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 187
    .line 188
    if-eq v1, v3, :cond_17

    .line 189
    .line 190
    return v2

    .line 191
    :cond_17
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 192
    .line 193
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 194
    .line 195
    if-eq v1, v3, :cond_18

    .line 196
    .line 197
    return v2

    .line 198
    :cond_18
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 199
    .line 200
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 201
    .line 202
    if-eq v1, v3, :cond_19

    .line 203
    .line 204
    return v2

    .line 205
    :cond_19
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 206
    .line 207
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 208
    .line 209
    if-eq v1, v3, :cond_1a

    .line 210
    .line 211
    return v2

    .line 212
    :cond_1a
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 213
    .line 214
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 215
    .line 216
    if-eq v1, v3, :cond_1b

    .line 217
    .line 218
    return v2

    .line 219
    :cond_1b
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 220
    .line 221
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 222
    .line 223
    if-eq v1, v3, :cond_1c

    .line 224
    .line 225
    return v2

    .line 226
    :cond_1c
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 227
    .line 228
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 229
    .line 230
    if-eq v1, v3, :cond_1d

    .line 231
    .line 232
    return v2

    .line 233
    :cond_1d
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 234
    .line 235
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 236
    .line 237
    if-eq v1, v3, :cond_1e

    .line 238
    .line 239
    return v2

    .line 240
    :cond_1e
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 241
    .line 242
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 243
    .line 244
    if-eq v1, v3, :cond_1f

    .line 245
    .line 246
    return v2

    .line 247
    :cond_1f
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 248
    .line 249
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 250
    .line 251
    if-eq v1, v3, :cond_20

    .line 252
    .line 253
    return v2

    .line 254
    :cond_20
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 255
    .line 256
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 257
    .line 258
    if-eq v1, v3, :cond_21

    .line 259
    .line 260
    return v2

    .line 261
    :cond_21
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 262
    .line 263
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 264
    .line 265
    if-eq v1, v3, :cond_22

    .line 266
    .line 267
    return v2

    .line 268
    :cond_22
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    .line 269
    .line 270
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    .line 271
    .line 272
    if-eq v1, v3, :cond_23

    .line 273
    .line 274
    return v2

    .line 275
    :cond_23
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    .line 276
    .line 277
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    .line 278
    .line 279
    if-eq v1, v3, :cond_24

    .line 280
    .line 281
    return v2

    .line 282
    :cond_24
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    .line 283
    .line 284
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    .line 285
    .line 286
    if-eq v1, v3, :cond_25

    .line 287
    .line 288
    return v2

    .line 289
    :cond_25
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    .line 290
    .line 291
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    .line 292
    .line 293
    if-eq v1, v3, :cond_26

    .line 294
    .line 295
    return v2

    .line 296
    :cond_26
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 297
    .line 298
    iget p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 299
    .line 300
    if-eq p0, p1, :cond_27

    .line 301
    .line 302
    return v2

    .line 303
    :cond_27
    return v0
.end method

.method public final getAcPlugUnlocking()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCentralLockingExternalStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCentralLockingInternalStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDoorOpenDriverSideFrontStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDoorOpenDriverSideRearStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDoorOpenPassengerSideFrontStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDoorOpenPassengerSideRearStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getEngineType()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release()Z
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;->OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 8
    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 12
    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 16
    .line 17
    if-eq v0, v1, :cond_1

    .line 18
    .line 19
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 24
    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0

    .line 30
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 31
    return p0
.end method

.method public final getHasOpenWindows$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 8
    .line 9
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 14
    .line 15
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 20
    .line 21
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isSunroofOpen$remoteparkassistcoremeb_release()Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 35
    return p0
.end method

.method public final getHvlmAcceptItSystemPeRange()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSunroofAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getSunroofCapAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getSunroofCapMode()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSunroofCapOpeningPercentage()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSunroofMode()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSunroofOpeningPercentage()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicleFrontOverhang()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    .line 2
    .line 3
    return p0
.end method

.method public final getVehicleLength()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    .line 2
    .line 3
    return p0
.end method

.method public final getVehicleRearOverhang()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 2
    .line 3
    return p0
.end method

.method public final getVehicleWheelbase()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    .line 2
    .line 3
    return p0
.end method

.method public final getVehicleWidth()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public final getWheelBase()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusDriverSideFront()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusDriverSideRear()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusPassengerSideFront()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusPassengerSideRear()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 35
    .line 36
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    add-int/2addr v2, v0

    .line 53
    mul-int/2addr v2, v1

    .line 54
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    add-int/2addr v0, v2

    .line 61
    mul-int/2addr v0, v1

    .line 62
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    add-int/2addr v2, v0

    .line 69
    mul-int/2addr v2, v1

    .line 70
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    add-int/2addr v0, v2

    .line 77
    mul-int/2addr v0, v1

    .line 78
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    add-int/2addr v2, v0

    .line 85
    mul-int/2addr v2, v1

    .line 86
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    add-int/2addr v0, v2

    .line 93
    mul-int/2addr v0, v1

    .line 94
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 95
    .line 96
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 101
    .line 102
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 107
    .line 108
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 113
    .line 114
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 119
    .line 120
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 131
    .line 132
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 137
    .line 138
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 143
    .line 144
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    add-int/2addr v2, v0

    .line 149
    mul-int/2addr v2, v1

    .line 150
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 151
    .line 152
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    add-int/2addr v0, v2

    .line 157
    mul-int/2addr v0, v1

    .line 158
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 159
    .line 160
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 161
    .line 162
    .line 163
    move-result v2

    .line 164
    add-int/2addr v2, v0

    .line 165
    mul-int/2addr v2, v1

    .line 166
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 167
    .line 168
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    add-int/2addr v0, v2

    .line 173
    mul-int/2addr v0, v1

    .line 174
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 175
    .line 176
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 181
    .line 182
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 187
    .line 188
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 189
    .line 190
    .line 191
    move-result v2

    .line 192
    add-int/2addr v2, v0

    .line 193
    mul-int/2addr v2, v1

    .line 194
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 195
    .line 196
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    add-int/2addr v0, v2

    .line 201
    mul-int/2addr v0, v1

    .line 202
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 203
    .line 204
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 205
    .line 206
    .line 207
    move-result v2

    .line 208
    add-int/2addr v2, v0

    .line 209
    mul-int/2addr v2, v1

    .line 210
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 211
    .line 212
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 213
    .line 214
    .line 215
    move-result v0

    .line 216
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 217
    .line 218
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 219
    .line 220
    .line 221
    move-result v2

    .line 222
    add-int/2addr v2, v0

    .line 223
    mul-int/2addr v2, v1

    .line 224
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 225
    .line 226
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 227
    .line 228
    .line 229
    move-result v0

    .line 230
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 231
    .line 232
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 233
    .line 234
    .line 235
    move-result v0

    .line 236
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    .line 237
    .line 238
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 239
    .line 240
    .line 241
    move-result v0

    .line 242
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    .line 243
    .line 244
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 245
    .line 246
    .line 247
    move-result v0

    .line 248
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    .line 249
    .line 250
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 251
    .line 252
    .line 253
    move-result v0

    .line 254
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    .line 255
    .line 256
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 257
    .line 258
    .line 259
    move-result v0

    .line 260
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 261
    .line 262
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 263
    .line 264
    .line 265
    move-result p0

    .line 266
    add-int/2addr p0, v0

    .line 267
    return p0
.end method

.method public final isBackAxleControlAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isComfortClosingPossible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorAlarmActivatedDriverSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorAlarmActivatedDriverSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorAlarmActivatedPassengerSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorAlarmActivatedPassengerSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorLockedDriverSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorLockedDriverSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorLockedPassengerSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorLockedPassengerSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isElectricalVehicle$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 2
    .line 3
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;->COMBUSTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final isGarageDoorOpenerAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isHavingDoorsError$remoteparkassistcoremeb_release()Z
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;->ERROR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 4
    .line 5
    if-eq v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 8
    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 12
    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 16
    .line 17
    if-ne p0, v1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public final isHoodOpen()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isSafeLockActive$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final isSunroofAvailable$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 13
    return p0
.end method

.method public final isSunroofOpen$remoteparkassistcoremeb_release()Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 6
    .line 7
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 12
    .line 13
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;->Sliding:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 14
    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    :cond_0
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 18
    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 22
    .line 23
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 24
    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 28
    .line 29
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;->Sliding:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 30
    .line 31
    if-ne p0, v0, :cond_2

    .line 32
    .line 33
    :cond_1
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_2
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public final isTrunkOpen()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isVehicleLocked$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->getCentralLockingActive()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 6
    .line 7
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 12
    .line 13
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Deckel_Lage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 39
    .line 40
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Deckel_Position:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 47
    .line 48
    .line 49
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 50
    .line 51
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_MD1_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 52
    .line 53
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 54
    .line 55
    .line 56
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 57
    .line 58
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_SAD2_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 59
    .line 60
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 61
    .line 62
    .line 63
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 64
    .line 65
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 70
    .line 71
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 72
    .line 73
    .line 74
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 75
    .line 76
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 86
    .line 87
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 92
    .line 93
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 97
    .line 98
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_FH_Oeffnung:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 108
    .line 109
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_verriegelt_intern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 114
    .line 115
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 119
    .line 120
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_verriegelt_extern_ist_02:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 127
    .line 128
    .line 129
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 130
    .line 131
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 132
    .line 133
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 134
    .line 135
    .line 136
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 137
    .line 138
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 139
    .line 140
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 141
    .line 142
    .line 143
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 144
    .line 145
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 146
    .line 147
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 148
    .line 149
    .line 150
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 151
    .line 152
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_verriegelt:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 153
    .line 154
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 155
    .line 156
    .line 157
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 158
    .line 159
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 160
    .line 161
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 162
    .line 163
    .line 164
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 165
    .line 166
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 167
    .line 168
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 169
    .line 170
    .line 171
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 172
    .line 173
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 174
    .line 175
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 176
    .line 177
    .line 178
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 179
    .line 180
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_gesafet:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 181
    .line 182
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 183
    .line 184
    .line 185
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 186
    .line 187
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 188
    .line 189
    .line 190
    move-result v1

    .line 191
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_FT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 192
    .line 193
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 194
    .line 195
    .line 196
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 197
    .line 198
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_BT_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 203
    .line 204
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 205
    .line 206
    .line 207
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 208
    .line 209
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 210
    .line 211
    .line 212
    move-result v1

    .line 213
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 214
    .line 215
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 216
    .line 217
    .line 218
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 219
    .line 220
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 221
    .line 222
    .line 223
    move-result v1

    .line 224
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HBFS_Tuer_Status:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 225
    .line 226
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 227
    .line 228
    .line 229
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 230
    .line 231
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_Heck_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 232
    .line 233
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 234
    .line 235
    .line 236
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 237
    .line 238
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_ZV_Frontdeckel_offen:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 239
    .line 240
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 241
    .line 242
    .line 243
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 244
    .line 245
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 246
    .line 247
    .line 248
    move-result v1

    .line 249
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HVLMAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 250
    .line 251
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 252
    .line 253
    .line 254
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 255
    .line 256
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 257
    .line 258
    .line 259
    move-result v1

    .line 260
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HVLMAutounlockAc:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 261
    .line 262
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 263
    .line 264
    .line 265
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 266
    .line 267
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 268
    .line 269
    .line 270
    move-result v1

    .line 271
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_EngineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 272
    .line 273
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 274
    .line 275
    .line 276
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 277
    .line 278
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_HAL_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 279
    .line 280
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 281
    .line 282
    .line 283
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 284
    .line 285
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 286
    .line 287
    .line 288
    move-result v1

    .line 289
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_WheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 290
    .line 291
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 292
    .line 293
    .line 294
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 295
    .line 296
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_GarageDoorOpener_Available:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 297
    .line 298
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 299
    .line 300
    .line 301
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 302
    .line 303
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->GwSm_SM_WinClPossible:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 304
    .line 305
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 306
    .line 307
    .line 308
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 309
    .line 310
    .line 311
    move-result-object p0

    .line 312
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 39

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 4
    .line 5
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 6
    .line 7
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;

    .line 8
    .line 9
    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 10
    .line 11
    iget-boolean v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofAvailable:Z

    .line 12
    .line 13
    iget-boolean v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->sunroofCapAvailable:Z

    .line 14
    .line 15
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 16
    .line 17
    iget-object v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 18
    .line 19
    iget-object v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 20
    .line 21
    iget-object v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 22
    .line 23
    iget-object v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingInternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 24
    .line 25
    iget-object v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->centralLockingExternalStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;

    .line 26
    .line 27
    iget-boolean v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideFront:Z

    .line 28
    .line 29
    iget-boolean v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideFront:Z

    .line 30
    .line 31
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedDriverSideRear:Z

    .line 32
    .line 33
    move/from16 v16, v15

    .line 34
    .line 35
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorLockedPassengerSideRear:Z

    .line 36
    .line 37
    move/from16 v17, v15

    .line 38
    .line 39
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideFront:Z

    .line 40
    .line 41
    move/from16 v18, v15

    .line 42
    .line 43
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideFront:Z

    .line 44
    .line 45
    move/from16 v19, v15

    .line 46
    .line 47
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedDriverSideRear:Z

    .line 48
    .line 49
    move/from16 v20, v15

    .line 50
    .line 51
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isDoorAlarmActivatedPassengerSideRear:Z

    .line 52
    .line 53
    move/from16 v21, v15

    .line 54
    .line 55
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 56
    .line 57
    move-object/from16 v22, v15

    .line 58
    .line 59
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideFrontStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 60
    .line 61
    move-object/from16 v23, v15

    .line 62
    .line 63
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenDriverSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 64
    .line 65
    move-object/from16 v24, v15

    .line 66
    .line 67
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->doorOpenPassengerSideRearStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;

    .line 68
    .line 69
    move-object/from16 v25, v15

    .line 70
    .line 71
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isTrunkOpen:Z

    .line 72
    .line 73
    move/from16 v26, v15

    .line 74
    .line 75
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHoodOpen:Z

    .line 76
    .line 77
    move/from16 v27, v15

    .line 78
    .line 79
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hvlmAcceptItSystemPeRange:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 80
    .line 81
    move-object/from16 v28, v15

    .line 82
    .line 83
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->acPlugUnlocking:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 84
    .line 85
    move-object/from16 v29, v15

    .line 86
    .line 87
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->engineType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;

    .line 88
    .line 89
    move-object/from16 v30, v15

    .line 90
    .line 91
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isBackAxleControlAvailable:Z

    .line 92
    .line 93
    move/from16 v31, v15

    .line 94
    .line 95
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->wheelBase:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;

    .line 96
    .line 97
    move-object/from16 v32, v15

    .line 98
    .line 99
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isGarageDoorOpenerAvailable:Z

    .line 100
    .line 101
    move/from16 v33, v15

    .line 102
    .line 103
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible:Z

    .line 104
    .line 105
    move/from16 v34, v15

    .line 106
    .line 107
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleLength:I

    .line 108
    .line 109
    move/from16 v35, v15

    .line 110
    .line 111
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWidth:I

    .line 112
    .line 113
    move/from16 v36, v15

    .line 114
    .line 115
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleWheelbase:I

    .line 116
    .line 117
    move/from16 v37, v15

    .line 118
    .line 119
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleFrontOverhang:I

    .line 120
    .line 121
    iget v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->vehicleRearOverhang:I

    .line 122
    .line 123
    move/from16 p0, v0

    .line 124
    .line 125
    new-instance v0, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    move/from16 v38, v15

    .line 128
    .line 129
    const-string v15, "C2PNormalPrioVehicleInfoMessagePPE(sunroofOpeningPercentage="

    .line 130
    .line 131
    invoke-direct {v0, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    const-string v1, ", sunroofMode="

    .line 138
    .line 139
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const-string v1, ", sunroofCapMode="

    .line 146
    .line 147
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v1, ", sunroofCapOpeningPercentage="

    .line 154
    .line 155
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    const-string v1, ", sunroofAvailable="

    .line 162
    .line 163
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    const-string v1, ", sunroofCapAvailable="

    .line 167
    .line 168
    const-string v2, ", windowStatusPassengerSideFront="

    .line 169
    .line 170
    invoke-static {v0, v5, v1, v6, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    const-string v1, ", windowStatusDriverSideFront="

    .line 177
    .line 178
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    const-string v1, ", windowStatusPassengerSideRear="

    .line 185
    .line 186
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 190
    .line 191
    .line 192
    const-string v1, ", windowStatusDriverSideRear="

    .line 193
    .line 194
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    const-string v1, ", centralLockingInternalStatus="

    .line 201
    .line 202
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    const-string v1, ", centralLockingExternalStatus="

    .line 209
    .line 210
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    invoke-virtual {v0, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    const-string v1, ", isDoorLockedDriverSideFront="

    .line 217
    .line 218
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    const-string v1, ", isDoorLockedPassengerSideFront="

    .line 222
    .line 223
    const-string v2, ", isDoorLockedDriverSideRear="

    .line 224
    .line 225
    invoke-static {v0, v13, v1, v14, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 226
    .line 227
    .line 228
    const-string v1, ", isDoorLockedPassengerSideRear="

    .line 229
    .line 230
    const-string v2, ", isDoorAlarmActivatedDriverSideFront="

    .line 231
    .line 232
    move/from16 v3, v16

    .line 233
    .line 234
    move/from16 v4, v17

    .line 235
    .line 236
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 237
    .line 238
    .line 239
    const-string v1, ", isDoorAlarmActivatedPassengerSideFront="

    .line 240
    .line 241
    const-string v2, ", isDoorAlarmActivatedDriverSideRear="

    .line 242
    .line 243
    move/from16 v3, v18

    .line 244
    .line 245
    move/from16 v4, v19

    .line 246
    .line 247
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 248
    .line 249
    .line 250
    const-string v1, ", isDoorAlarmActivatedPassengerSideRear="

    .line 251
    .line 252
    const-string v2, ", doorOpenDriverSideFrontStatus="

    .line 253
    .line 254
    move/from16 v3, v20

    .line 255
    .line 256
    move/from16 v4, v21

    .line 257
    .line 258
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 259
    .line 260
    .line 261
    move-object/from16 v1, v22

    .line 262
    .line 263
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    const-string v1, ", doorOpenPassengerSideFrontStatus="

    .line 267
    .line 268
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    move-object/from16 v1, v23

    .line 272
    .line 273
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 274
    .line 275
    .line 276
    const-string v1, ", doorOpenDriverSideRearStatus="

    .line 277
    .line 278
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    move-object/from16 v1, v24

    .line 282
    .line 283
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    const-string v1, ", doorOpenPassengerSideRearStatus="

    .line 287
    .line 288
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 289
    .line 290
    .line 291
    move-object/from16 v1, v25

    .line 292
    .line 293
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    const-string v1, ", isTrunkOpen="

    .line 297
    .line 298
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    const-string v1, ", isHoodOpen="

    .line 302
    .line 303
    const-string v2, ", hvlmAcceptItSystemPeRange="

    .line 304
    .line 305
    move/from16 v3, v26

    .line 306
    .line 307
    move/from16 v4, v27

    .line 308
    .line 309
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 310
    .line 311
    .line 312
    move-object/from16 v1, v28

    .line 313
    .line 314
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 315
    .line 316
    .line 317
    const-string v1, ", acPlugUnlocking="

    .line 318
    .line 319
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 320
    .line 321
    .line 322
    move-object/from16 v1, v29

    .line 323
    .line 324
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 325
    .line 326
    .line 327
    const-string v1, ", engineType="

    .line 328
    .line 329
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 330
    .line 331
    .line 332
    move-object/from16 v1, v30

    .line 333
    .line 334
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 335
    .line 336
    .line 337
    const-string v1, ", isBackAxleControlAvailable="

    .line 338
    .line 339
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 340
    .line 341
    .line 342
    move/from16 v1, v31

    .line 343
    .line 344
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 345
    .line 346
    .line 347
    const-string v1, ", wheelBase="

    .line 348
    .line 349
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 350
    .line 351
    .line 352
    move-object/from16 v1, v32

    .line 353
    .line 354
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 355
    .line 356
    .line 357
    const-string v1, ", isGarageDoorOpenerAvailable="

    .line 358
    .line 359
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 360
    .line 361
    .line 362
    move/from16 v1, v33

    .line 363
    .line 364
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 365
    .line 366
    .line 367
    const-string v1, ", isComfortClosingPossible="

    .line 368
    .line 369
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 370
    .line 371
    .line 372
    move/from16 v1, v34

    .line 373
    .line 374
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 375
    .line 376
    .line 377
    const-string v1, ", vehicleLength="

    .line 378
    .line 379
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 380
    .line 381
    .line 382
    move/from16 v1, v35

    .line 383
    .line 384
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    const-string v1, ", vehicleWidth="

    .line 388
    .line 389
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 390
    .line 391
    .line 392
    const-string v1, ", vehicleWheelbase="

    .line 393
    .line 394
    const-string v2, ", vehicleFrontOverhang="

    .line 395
    .line 396
    move/from16 v3, v36

    .line 397
    .line 398
    move/from16 v4, v37

    .line 399
    .line 400
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 401
    .line 402
    .line 403
    move/from16 v1, v38

    .line 404
    .line 405
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 406
    .line 407
    .line 408
    const-string v1, ", vehicleRearOverhang="

    .line 409
    .line 410
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 411
    .line 412
    .line 413
    move/from16 v1, p0

    .line 414
    .line 415
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 416
    .line 417
    .line 418
    const-string v1, ")"

    .line 419
    .line 420
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 421
    .line 422
    .line 423
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    return-object v0
.end method
