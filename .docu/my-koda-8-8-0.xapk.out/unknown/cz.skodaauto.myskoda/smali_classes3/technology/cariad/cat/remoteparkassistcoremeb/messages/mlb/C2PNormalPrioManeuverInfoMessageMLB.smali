.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000d\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0010\u0012\n\u0002\u0008$\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0018\n\u0002\u0018\u0002\n\u0002\u0008\u000e\u0008\u0086\u0008\u0018\u0000 r2\u00020\u0001:\u0001rB\u00d9\u0001\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\u0008\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\n\u0012\u0008\u0008\u0002\u0010\r\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u000e\u0012\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u000e\u0012\u0008\u0008\u0002\u0010\u0011\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u0013\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u0019\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u001b\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u001d\u001a\u00020\u0016\u0012\u0008\u0008\u0002\u0010\u001e\u001a\u00020\u0016\u00a2\u0006\u0004\u0008\u001f\u0010 J\u000f\u0010\"\u001a\u00020!H\u0016\u00a2\u0006\u0004\u0008\"\u0010#J\u0010\u0010$\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008$\u0010%J\u0010\u0010&\u001a\u00020\u0004H\u00c6\u0003\u00a2\u0006\u0004\u0008&\u0010\'J\u0010\u0010(\u001a\u00020\u0006H\u00c6\u0003\u00a2\u0006\u0004\u0008(\u0010)J\u0010\u0010*\u001a\u00020\u0008H\u00c6\u0003\u00a2\u0006\u0004\u0008*\u0010+J\u0010\u0010,\u001a\u00020\nH\u00c6\u0003\u00a2\u0006\u0004\u0008,\u0010-J\u0010\u0010.\u001a\u00020\u000cH\u00c6\u0003\u00a2\u0006\u0004\u0008.\u0010/J\u0010\u00102\u001a\u00020\u000eH\u00c6\u0003\u00a2\u0006\u0004\u00080\u00101J\u0010\u00104\u001a\u00020\u000eH\u00c6\u0003\u00a2\u0006\u0004\u00083\u00101J\u0010\u00105\u001a\u00020\u000cH\u00c6\u0003\u00a2\u0006\u0004\u00085\u0010/J\u0010\u00106\u001a\u00020\u000cH\u00c6\u0003\u00a2\u0006\u0004\u00086\u0010/J\u0010\u00107\u001a\u00020\u000cH\u00c6\u0003\u00a2\u0006\u0004\u00087\u0010/J\u0010\u00108\u001a\u00020\u000cH\u00c6\u0003\u00a2\u0006\u0004\u00088\u0010/J\u0010\u00109\u001a\u00020\u000cH\u00c6\u0003\u00a2\u0006\u0004\u00089\u0010/J\u0010\u0010:\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008:\u0010;J\u0010\u0010<\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008<\u0010;J\u0010\u0010=\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008=\u0010;J\u0010\u0010>\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008>\u0010;J\u0010\u0010?\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008?\u0010;J\u0010\u0010@\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008@\u0010;J\u0010\u0010A\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008A\u0010;J\u0010\u0010B\u001a\u00020\u0016H\u00c6\u0003\u00a2\u0006\u0004\u0008B\u0010;J\u00e2\u0001\u0010E\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00042\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00062\u0008\u0008\u0002\u0010\t\u001a\u00020\u00082\u0008\u0008\u0002\u0010\u000b\u001a\u00020\n2\u0008\u0008\u0002\u0010\r\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u000e2\u0008\u0008\u0002\u0010\u0011\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u0013\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u000c2\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u0019\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u001b\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u001d\u001a\u00020\u00162\u0008\u0008\u0002\u0010\u001e\u001a\u00020\u0016H\u00c6\u0001\u00a2\u0006\u0004\u0008C\u0010DJ\u0010\u0010G\u001a\u00020FH\u00d6\u0001\u00a2\u0006\u0004\u0008G\u0010HJ\u0010\u0010J\u001a\u00020IH\u00d6\u0001\u00a2\u0006\u0004\u0008J\u0010KJ\u001a\u0010N\u001a\u00020\u00162\u0008\u0010M\u001a\u0004\u0018\u00010LH\u00d6\u0003\u00a2\u0006\u0004\u0008N\u0010OR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010P\u001a\u0004\u0008Q\u0010%R\u0017\u0010\u0005\u001a\u00020\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010R\u001a\u0004\u0008S\u0010\'R\u0017\u0010\u0007\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010T\u001a\u0004\u0008U\u0010)R\u0017\u0010\t\u001a\u00020\u00088\u0006\u00a2\u0006\u000c\n\u0004\u0008\t\u0010V\u001a\u0004\u0008W\u0010+R\u0017\u0010\u000b\u001a\u00020\n8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000b\u0010X\u001a\u0004\u0008Y\u0010-R\u0017\u0010\r\u001a\u00020\u000c8\u0006\u00a2\u0006\u000c\n\u0004\u0008\r\u0010Z\u001a\u0004\u0008[\u0010/R\u0017\u0010\u000f\u001a\u00020\u000e8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000f\u0010\\\u001a\u0004\u0008]\u00101R\u0017\u0010\u0010\u001a\u00020\u000e8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0010\u0010\\\u001a\u0004\u0008^\u00101R\u0017\u0010\u0011\u001a\u00020\u000c8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0011\u0010Z\u001a\u0004\u0008_\u0010/R\u0017\u0010\u0012\u001a\u00020\u000c8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0012\u0010Z\u001a\u0004\u0008`\u0010/R\u0017\u0010\u0013\u001a\u00020\u000c8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0013\u0010Z\u001a\u0004\u0008a\u0010/R\u0017\u0010\u0014\u001a\u00020\u000c8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0014\u0010Z\u001a\u0004\u0008b\u0010/R\u0017\u0010\u0015\u001a\u00020\u000c8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0015\u0010Z\u001a\u0004\u0008c\u0010/R\u0017\u0010\u0017\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0017\u0010d\u001a\u0004\u0008\u0017\u0010;R\u0017\u0010\u0018\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0018\u0010d\u001a\u0004\u0008\u0018\u0010;R\u0017\u0010\u0019\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0019\u0010d\u001a\u0004\u0008\u0019\u0010;R\u0017\u0010\u001a\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u001a\u0010d\u001a\u0004\u0008\u001a\u0010;R\u0017\u0010\u001b\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u001b\u0010d\u001a\u0004\u0008\u001b\u0010;R\u0017\u0010\u001c\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u001c\u0010d\u001a\u0004\u0008\u001c\u0010;R\u0017\u0010\u001d\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u001d\u0010d\u001a\u0004\u0008\u001d\u0010;R\u0017\u0010\u001e\u001a\u00020\u00168\u0006\u00a2\u0006\u000c\n\u0004\u0008\u001e\u0010d\u001a\u0004\u0008\u001e\u0010;R\u001a\u0010f\u001a\u00020e8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008f\u0010g\u001a\u0004\u0008h\u0010iR\u0014\u0010k\u001a\u00020\u00168@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008j\u0010;R\u0014\u0010m\u001a\u00020\u00168@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008l\u0010;R\u0014\u0010o\u001a\u00020\u00168@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008n\u0010;R\u0014\u0010p\u001a\u00020\u00168BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008p\u0010;R\u0014\u0010q\u001a\u00020\u00168BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008q\u0010;\u00a8\u0006s"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;",
        "parkingSideStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;",
        "parkingScenarioStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;",
        "parkingManeuverStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;",
        "parkingDirectionStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;",
        "parkingReversibleStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "windowStatusMultifunctionCover",
        "Llx0/s;",
        "multifunctionCoverLocation",
        "slidePopTopLocation",
        "windowStatusSlidePopTop",
        "windowStatusPassengerSideFront",
        "windowStatusDriverSideFront",
        "windowStatusPassengerSideRear",
        "windowStatusDriverSideRear",
        "",
        "isCentralLockingInternalActive",
        "isCentralLockingExternalActive",
        "isDoorOpenDriverSideFront",
        "isDoorOpenPassengerSideFront",
        "isDoorOpenDriverSideRear",
        "isDoorOpenPassengerSideRear",
        "isDoorOpenTrunk",
        "isDoorOpenHood",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZLkotlin/jvm/internal/g;)V",
        "",
        "toBytes",
        "()[B",
        "component1",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;",
        "component2",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;",
        "component3",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;",
        "component4",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;",
        "component5",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;",
        "component6",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "component7-w2LRezQ",
        "()B",
        "component7",
        "component8-w2LRezQ",
        "component8",
        "component9",
        "component10",
        "component11",
        "component12",
        "component13",
        "component14",
        "()Z",
        "component15",
        "component16",
        "component17",
        "component18",
        "component19",
        "component20",
        "component21",
        "copy-e-SI6bs",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;",
        "copy",
        "",
        "toString",
        "()Ljava/lang/String;",
        "",
        "hashCode",
        "()I",
        "",
        "other",
        "equals",
        "(Ljava/lang/Object;)Z",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;",
        "getParkingSideStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;",
        "getParkingScenarioStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;",
        "getParkingManeuverStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;",
        "getParkingDirectionStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;",
        "getParkingReversibleStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "getWindowStatusMultifunctionCover",
        "B",
        "getMultifunctionCoverLocation-w2LRezQ",
        "getSlidePopTopLocation-w2LRezQ",
        "getWindowStatusSlidePopTop",
        "getWindowStatusPassengerSideFront",
        "getWindowStatusDriverSideFront",
        "getWindowStatusPassengerSideRear",
        "getWindowStatusDriverSideRear",
        "Z",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getHasOpenWindows$remoteparkassistcoremeb_release",
        "hasOpenWindows",
        "getHasOpenDoors$remoteparkassistcoremeb_release",
        "hasOpenDoors",
        "isVehicleLocked$remoteparkassistcoremeb_release",
        "isVehicleLocked",
        "isCentralLockingActive",
        "isSunroofClosed",
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
.field private static final BCM1_MH_SWITCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final BT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB$Companion;

.field private static final FT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final HBFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final HFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final MD1_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_MANEUVER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SIDE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SAD2_COVER_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SAD2_COVER_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isCentralLockingExternalActive:Z

.field private final isCentralLockingInternalActive:Z

.field private final isDoorOpenDriverSideFront:Z

.field private final isDoorOpenDriverSideRear:Z

.field private final isDoorOpenHood:Z

.field private final isDoorOpenPassengerSideFront:Z

.field private final isDoorOpenPassengerSideRear:Z

.field private final isDoorOpenTrunk:Z

.field private final multifunctionCoverLocation:B

.field private final parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

.field private final parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

.field private final parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

.field private final parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

.field private final parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

.field private final slidePopTopLocation:B

.field private final windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB$Companion;

    .line 8
    .line 9
    const/16 v0, 0x22

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->messageID:B

    .line 12
    .line 13
    const-wide v1, 0x5250410201000000L    # 3.2333841869179016E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->address:J

    .line 19
    .line 20
    const/4 v1, 0x3

    .line 21
    sput-byte v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->priority:B

    .line 22
    .line 23
    const/16 v2, 0x9

    .line 24
    .line 25
    sput v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->byteLength:I

    .line 26
    .line 27
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 28
    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v5, 0x2

    .line 31
    invoke-direct {v3, v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 32
    .line 33
    .line 34
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_SIDE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 35
    .line 36
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 37
    .line 38
    invoke-direct {v3, v5, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 39
    .line 40
    .line 41
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 42
    .line 43
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 44
    .line 45
    const/4 v3, 0x5

    .line 46
    invoke-direct {v1, v3, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 47
    .line 48
    .line 49
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_MANEUVER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 52
    .line 53
    const/4 v3, 0x7

    .line 54
    invoke-direct {v1, v3, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 55
    .line 56
    .line 57
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 58
    .line 59
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 60
    .line 61
    const/4 v4, 0x1

    .line 62
    invoke-direct {v1, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 63
    .line 64
    .line 65
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 66
    .line 67
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 68
    .line 69
    const/16 v2, 0xa

    .line 70
    .line 71
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 72
    .line 73
    .line 74
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 75
    .line 76
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 77
    .line 78
    const/16 v2, 0x11

    .line 79
    .line 80
    invoke-direct {v1, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 81
    .line 82
    .line 83
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->MD1_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 84
    .line 85
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 86
    .line 87
    const/16 v2, 0x12

    .line 88
    .line 89
    invoke-direct {v1, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 90
    .line 91
    .line 92
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->SAD2_COVER_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 93
    .line 94
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 95
    .line 96
    const/16 v2, 0x13

    .line 97
    .line 98
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 99
    .line 100
    .line 101
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->SAD2_COVER_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 102
    .line 103
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 104
    .line 105
    const/16 v2, 0x1a

    .line 106
    .line 107
    const/16 v3, 0x8

    .line 108
    .line 109
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 110
    .line 111
    .line 112
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->BT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 113
    .line 114
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 115
    .line 116
    invoke-direct {v1, v0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 117
    .line 118
    .line 119
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->FT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 120
    .line 121
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 122
    .line 123
    const/16 v1, 0x2a

    .line 124
    .line 125
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 126
    .line 127
    .line 128
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->HBFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 129
    .line 130
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 131
    .line 132
    const/16 v1, 0x32

    .line 133
    .line 134
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 135
    .line 136
    .line 137
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->HFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 138
    .line 139
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 140
    .line 141
    const/16 v1, 0x3a

    .line 142
    .line 143
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 144
    .line 145
    .line 146
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 147
    .line 148
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 149
    .line 150
    const/16 v1, 0x3b

    .line 151
    .line 152
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 153
    .line 154
    .line 155
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 156
    .line 157
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 158
    .line 159
    const/16 v1, 0x3c

    .line 160
    .line 161
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 162
    .line 163
    .line 164
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 165
    .line 166
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 167
    .line 168
    const/16 v1, 0x3d

    .line 169
    .line 170
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 171
    .line 172
    .line 173
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 174
    .line 175
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 176
    .line 177
    const/16 v1, 0x3e

    .line 178
    .line 179
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 180
    .line 181
    .line 182
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 183
    .line 184
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 185
    .line 186
    const/16 v1, 0x3f

    .line 187
    .line 188
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 189
    .line 190
    .line 191
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 192
    .line 193
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 194
    .line 195
    const/16 v1, 0x40

    .line 196
    .line 197
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 198
    .line 199
    .line 200
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 201
    .line 202
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 203
    .line 204
    const/16 v1, 0x41

    .line 205
    .line 206
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 207
    .line 208
    .line 209
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->BCM1_MH_SWITCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 210
    .line 211
    return-void
.end method

.method private constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZ)V
    .locals 6

    move-object v0, p9

    move-object/from16 v1, p10

    move-object/from16 v2, p11

    move-object/from16 v3, p12

    move-object/from16 v4, p13

    const-string v5, "parkingSideStatus"

    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "parkingScenarioStatus"

    invoke-static {p2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "parkingManeuverStatus"

    invoke-static {p3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "parkingDirectionStatus"

    invoke-static {p4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "parkingReversibleStatus"

    invoke-static {p5, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "windowStatusMultifunctionCover"

    invoke-static {p6, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "windowStatusSlidePopTop"

    invoke-static {p9, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "windowStatusPassengerSideFront"

    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "windowStatusDriverSideFront"

    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "windowStatusPassengerSideRear"

    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "windowStatusDriverSideRear"

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 4
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 6
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 7
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 8
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 9
    iput-byte p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    move p1, p8

    .line 10
    iput-byte p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 12
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 13
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 14
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 15
    iput-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    move/from16 p1, p14

    .line 16
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    move/from16 p1, p15

    .line 17
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    move/from16 p1, p16

    .line 18
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    move/from16 p1, p17

    .line 19
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    move/from16 p1, p18

    .line 20
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    move/from16 p1, p19

    .line 21
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    move/from16 p1, p20

    .line 22
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    move/from16 p1, p21

    .line 23
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 24
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILkotlin/jvm/internal/g;)V
    .locals 22

    move/from16 v0, p22

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 25
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    goto :goto_0

    :cond_0
    move-object/from16 v1, p1

    :goto_0
    and-int/lit8 v2, v0, 0x2

    if-eqz v2, :cond_1

    .line 26
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    goto :goto_1

    :cond_1
    move-object/from16 v2, p2

    :goto_1
    and-int/lit8 v3, v0, 0x4

    if-eqz v3, :cond_2

    .line 27
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    goto :goto_2

    :cond_2
    move-object/from16 v3, p3

    :goto_2
    and-int/lit8 v4, v0, 0x8

    if-eqz v4, :cond_3

    .line 28
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    goto :goto_3

    :cond_3
    move-object/from16 v4, p4

    :goto_3
    and-int/lit8 v5, v0, 0x10

    if-eqz v5, :cond_4

    .line 29
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;->NOT_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    goto :goto_4

    :cond_4
    move-object/from16 v5, p5

    :goto_4
    and-int/lit8 v6, v0, 0x20

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x1

    if-eqz v6, :cond_5

    .line 30
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v6, v8, v9, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_5

    :cond_5
    move-object/from16 v6, p6

    :goto_5
    and-int/lit8 v10, v0, 0x40

    if-eqz v10, :cond_6

    int-to-byte v10, v8

    goto :goto_6

    :cond_6
    move/from16 v10, p7

    :goto_6
    and-int/lit16 v11, v0, 0x80

    if-eqz v11, :cond_7

    int-to-byte v11, v8

    goto :goto_7

    :cond_7
    move/from16 v11, p8

    :goto_7
    and-int/lit16 v12, v0, 0x100

    if-eqz v12, :cond_8

    .line 31
    new-instance v12, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v12, v8, v9, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_8

    :cond_8
    move-object/from16 v12, p9

    :goto_8
    and-int/lit16 v13, v0, 0x200

    if-eqz v13, :cond_9

    .line 32
    new-instance v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v13, v8, v9, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_9

    :cond_9
    move-object/from16 v13, p10

    :goto_9
    and-int/lit16 v14, v0, 0x400

    if-eqz v14, :cond_a

    .line 33
    new-instance v14, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v14, v8, v9, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_a

    :cond_a
    move-object/from16 v14, p11

    :goto_a
    and-int/lit16 v15, v0, 0x800

    if-eqz v15, :cond_b

    .line 34
    new-instance v15, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v15, v8, v9, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_b

    :cond_b
    move-object/from16 v15, p12

    :goto_b
    and-int/lit16 v7, v0, 0x1000

    if-eqz v7, :cond_c

    .line 35
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    move-object/from16 p23, v1

    const/4 v1, 0x0

    invoke-direct {v7, v8, v9, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_c

    :cond_c
    move-object/from16 p23, v1

    move-object/from16 v7, p13

    :goto_c
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_d

    move v1, v8

    goto :goto_d

    :cond_d
    move/from16 v1, p14

    :goto_d
    and-int/lit16 v9, v0, 0x4000

    if-eqz v9, :cond_e

    move v9, v8

    goto :goto_e

    :cond_e
    move/from16 v9, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v0, v16

    if-eqz v16, :cond_f

    move/from16 v16, v8

    goto :goto_f

    :cond_f
    move/from16 v16, p16

    :goto_f
    const/high16 v17, 0x10000

    and-int v17, v0, v17

    if-eqz v17, :cond_10

    move/from16 v17, v8

    goto :goto_10

    :cond_10
    move/from16 v17, p17

    :goto_10
    const/high16 v18, 0x20000

    and-int v18, v0, v18

    if-eqz v18, :cond_11

    move/from16 v18, v8

    goto :goto_11

    :cond_11
    move/from16 v18, p18

    :goto_11
    const/high16 v19, 0x40000

    and-int v19, v0, v19

    if-eqz v19, :cond_12

    move/from16 v19, v8

    goto :goto_12

    :cond_12
    move/from16 v19, p19

    :goto_12
    const/high16 v20, 0x80000

    and-int v20, v0, v20

    if-eqz v20, :cond_13

    move/from16 v20, v8

    goto :goto_13

    :cond_13
    move/from16 v20, p20

    :goto_13
    const/high16 v21, 0x100000

    and-int v0, v0, v21

    if-eqz v0, :cond_14

    goto :goto_14

    :cond_14
    move/from16 v8, p21

    :goto_14
    const/4 v0, 0x0

    move-object/from16 p1, p0

    move-object/from16 p2, p23

    move-object/from16 p23, v0

    move/from16 p15, v1

    move-object/from16 p3, v2

    move-object/from16 p4, v3

    move-object/from16 p5, v4

    move-object/from16 p6, v5

    move-object/from16 p7, v6

    move-object/from16 p14, v7

    move/from16 p22, v8

    move/from16 p16, v9

    move/from16 p8, v10

    move/from16 p9, v11

    move-object/from16 p10, v12

    move-object/from16 p11, v13

    move-object/from16 p12, v14

    move-object/from16 p13, v15

    move/from16 p17, v16

    move/from16 p18, v17

    move/from16 p19, v18

    move/from16 p20, v19

    move/from16 p21, v20

    .line 36
    invoke-direct/range {p1 .. p23}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZLkotlin/jvm/internal/g;)V

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p21}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZ)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getBCM1_MH_SWITCH$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->BCM1_MH_SWITCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getBT_FH_APERTURE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->BT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getFT_FH_APERTURE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->FT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getHBFS_FH_APERTURE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->HBFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getHFS_FH_APERTURE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->HFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMD1_LOCATION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->MD1_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMD1_POSITION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPARKING_DIRECTION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_MANEUVER$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_MANEUVER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_REVERSIBLE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SIDE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_SIDE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getSAD2_COVER_LOCATION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->SAD2_COVER_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSAD2_COVER_POSITION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->SAD2_COVER_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_BT_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_CENTRAL_LOCKING_EXTERNAL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_CENTRAL_LOCKING_INTERNAL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_FT_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_HBFS_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_HD_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_HFS_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy-e-SI6bs$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p22

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    goto :goto_0

    :cond_0
    move-object/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-object v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-object v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_5

    :cond_5
    move-object/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-byte v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    goto :goto_6

    :cond_6
    move/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-byte v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    goto :goto_7

    :cond_7
    move/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-object v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_8

    :cond_8
    move-object/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-object v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_9

    :cond_9
    move-object/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget-object v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_a

    :cond_a
    move-object/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-object v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_b

    :cond_b
    move-object/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget-object v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_c

    :cond_c
    move-object/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    goto :goto_d

    :cond_d
    move/from16 v15, p14

    :goto_d
    move-object/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-boolean v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    goto :goto_e

    :cond_e
    move/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    goto :goto_f

    :cond_f
    move/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p22, v16

    move/from16 p2, v1

    if-eqz v16, :cond_10

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    goto :goto_10

    :cond_10
    move/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p22, v16

    move/from16 p3, v1

    if-eqz v16, :cond_11

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    goto :goto_11

    :cond_11
    move/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p22, v16

    move/from16 p4, v1

    if-eqz v16, :cond_12

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    goto :goto_12

    :cond_12
    move/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p22, v16

    move/from16 p5, v1

    if-eqz v16, :cond_13

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    goto :goto_13

    :cond_13
    move/from16 v1, p20

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p22, v16

    if-eqz v16, :cond_14

    move/from16 p6, v1

    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    move/from16 p21, p6

    move/from16 p22, v1

    :goto_14
    move/from16 p17, p2

    move/from16 p18, p3

    move/from16 p19, p4

    move/from16 p20, p5

    move/from16 p16, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move-object/from16 p7, v7

    move/from16 p8, v8

    move/from16 p9, v9

    move-object/from16 p10, v10

    move-object/from16 p11, v11

    move-object/from16 p12, v12

    move-object/from16 p13, v13

    move-object/from16 p14, v14

    move/from16 p15, v15

    move-object/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_15

    :cond_14
    move/from16 p22, p21

    move/from16 p21, v1

    goto :goto_14

    :goto_15
    invoke-virtual/range {p1 .. p22}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->copy-e-SI6bs(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    move-result-object v0

    return-object v0
.end method

.method private final isCentralLockingActive()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

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

.method private final isSunroofClosed()Z
    .locals 3

    .line 1
    iget-byte v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    int-to-byte v2, v1

    .line 5
    if-ne v0, v2, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 8
    .line 9
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget-byte v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 14
    .line 15
    if-ne v0, v2, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 18
    .line 19
    instance-of p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_0
    return v1
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component14()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component15()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component16()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component17()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component18()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component19()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component21()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 2
    .line 3
    return p0
.end method

.method public final component8-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 2
    .line 3
    return p0
.end method

.method public final component9()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy-e-SI6bs(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;
    .locals 24

    .line 1
    const-string v0, "parkingSideStatus"

    move-object/from16 v2, p1

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingScenarioStatus"

    move-object/from16 v3, p2

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingManeuverStatus"

    move-object/from16 v4, p3

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingDirectionStatus"

    move-object/from16 v5, p4

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingReversibleStatus"

    move-object/from16 v6, p5

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusMultifunctionCover"

    move-object/from16 v7, p6

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusSlidePopTop"

    move-object/from16 v10, p9

    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideFront"

    move-object/from16 v11, p10

    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideFront"

    move-object/from16 v12, p11

    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideRear"

    move-object/from16 v13, p12

    invoke-static {v13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideRear"

    move-object/from16 v14, p13

    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    const/16 v23, 0x0

    move/from16 v8, p7

    move/from16 v9, p8

    move/from16 v15, p14

    move/from16 v16, p15

    move/from16 v17, p16

    move/from16 v18, p17

    move/from16 v19, p18

    move/from16 v20, p19

    move/from16 v21, p20

    move/from16 v22, p21

    invoke-direct/range {v1 .. v23}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZLkotlin/jvm/internal/g;)V

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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 21
    .line 22
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 28
    .line 29
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 35
    .line 36
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 42
    .line 43
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 49
    .line 50
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 51
    .line 52
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 60
    .line 61
    iget-byte v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 67
    .line 68
    iget-byte v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 69
    .line 70
    if-eq v1, v3, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 74
    .line 75
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 76
    .line 77
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 85
    .line 86
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 87
    .line 88
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-nez v1, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 96
    .line 97
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 98
    .line 99
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-nez v1, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 107
    .line 108
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 109
    .line 110
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-nez v1, :cond_d

    .line 115
    .line 116
    return v2

    .line 117
    :cond_d
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 118
    .line 119
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 120
    .line 121
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    if-nez v1, :cond_e

    .line 126
    .line 127
    return v2

    .line 128
    :cond_e
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 129
    .line 130
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 131
    .line 132
    if-eq v1, v3, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 136
    .line 137
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 138
    .line 139
    if-eq v1, v3, :cond_10

    .line 140
    .line 141
    return v2

    .line 142
    :cond_10
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 143
    .line 144
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 145
    .line 146
    if-eq v1, v3, :cond_11

    .line 147
    .line 148
    return v2

    .line 149
    :cond_11
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 150
    .line 151
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 152
    .line 153
    if-eq v1, v3, :cond_12

    .line 154
    .line 155
    return v2

    .line 156
    :cond_12
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 157
    .line 158
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 159
    .line 160
    if-eq v1, v3, :cond_13

    .line 161
    .line 162
    return v2

    .line 163
    :cond_13
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 164
    .line 165
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 166
    .line 167
    if-eq v1, v3, :cond_14

    .line 168
    .line 169
    return v2

    .line 170
    :cond_14
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 171
    .line 172
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 173
    .line 174
    if-eq v1, v3, :cond_15

    .line 175
    .line 176
    return v2

    .line 177
    :cond_15
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 178
    .line 179
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 180
    .line 181
    if-eq p0, p1, :cond_16

    .line 182
    .line 183
    return v2

    .line 184
    :cond_16
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHasOpenDoors$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 29
    return p0
.end method

.method public final getHasOpenWindows$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 8
    .line 9
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 14
    .line 15
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 20
    .line 21
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isSunroofClosed()Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-nez p0, :cond_0

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

.method public final getMultifunctionCoverLocation-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingDirectionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuverStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingReversibleStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingScenarioStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSlidePopTopLocation-w2LRezQ()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 2
    .line 3
    return p0
.end method

.method public final getWindowStatusDriverSideFront()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusDriverSideRear()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusMultifunctionCover()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusPassengerSideFront()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusPassengerSideRear()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusSlidePopTop()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

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
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

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
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    add-int/2addr v0, v2

    .line 41
    mul-int/2addr v0, v1

    .line 42
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    add-int/2addr v2, v0

    .line 49
    mul-int/2addr v2, v1

    .line 50
    iget-byte v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 51
    .line 52
    invoke-static {v0}, Ljava/lang/Byte;->hashCode(B)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    add-int/2addr v0, v2

    .line 57
    mul-int/2addr v0, v1

    .line 58
    iget-byte v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 59
    .line 60
    invoke-static {v2}, Ljava/lang/Byte;->hashCode(B)I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    add-int/2addr v2, v0

    .line 65
    mul-int/2addr v2, v1

    .line 66
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    add-int/2addr v0, v2

    .line 73
    mul-int/2addr v0, v1

    .line 74
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    add-int/2addr v2, v0

    .line 81
    mul-int/2addr v2, v1

    .line 82
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 83
    .line 84
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    add-int/2addr v0, v2

    .line 89
    mul-int/2addr v0, v1

    .line 90
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 91
    .line 92
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    add-int/2addr v2, v0

    .line 97
    mul-int/2addr v2, v1

    .line 98
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    add-int/2addr v0, v2

    .line 105
    mul-int/2addr v0, v1

    .line 106
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 107
    .line 108
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 113
    .line 114
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 119
    .line 120
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 131
    .line 132
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 137
    .line 138
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 143
    .line 144
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 149
    .line 150
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    add-int/2addr p0, v0

    .line 155
    return p0
.end method

.method public final isCentralLockingExternalActive()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isCentralLockingInternalActive()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenDriverSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenDriverSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenHood()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenPassengerSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenPassengerSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenTrunk()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isVehicleLocked$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->getHasOpenDoors$remoteparkassistcoremeb_release()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingActive()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_SIDE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 12
    .line 13
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_SCENARIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_MANEUVER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 56
    .line 57
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 61
    .line 62
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 69
    .line 70
    .line 71
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 72
    .line 73
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->MD1_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 74
    .line 75
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 76
    .line 77
    .line 78
    iget-byte v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 79
    .line 80
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->SAD2_COVER_LOCATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-X9TprxQ([BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 86
    .line 87
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->SAD2_COVER_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 92
    .line 93
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 97
    .line 98
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->BT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 108
    .line 109
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->FT_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 114
    .line 115
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 119
    .line 120
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->HBFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 127
    .line 128
    .line 129
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 130
    .line 131
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->HFS_FH_APERTURE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 136
    .line 137
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 138
    .line 139
    .line 140
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 141
    .line 142
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 143
    .line 144
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 145
    .line 146
    .line 147
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 148
    .line 149
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 150
    .line 151
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 152
    .line 153
    .line 154
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 155
    .line 156
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 157
    .line 158
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 159
    .line 160
    .line 161
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 162
    .line 163
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 164
    .line 165
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 166
    .line 167
    .line 168
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 169
    .line 170
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 171
    .line 172
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 173
    .line 174
    .line 175
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 176
    .line 177
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 178
    .line 179
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 180
    .line 181
    .line 182
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 183
    .line 184
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 185
    .line 186
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 187
    .line 188
    .line 189
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 190
    .line 191
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->BCM1_MH_SWITCH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 192
    .line 193
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 194
    .line 195
    .line 196
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 4
    .line 5
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingScenarioStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 6
    .line 7
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingManeuverStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 8
    .line 9
    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingDirectionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 10
    .line 11
    iget-object v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->parkingReversibleStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 12
    .line 13
    iget-object v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusMultifunctionCover:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 14
    .line 15
    iget-byte v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->multifunctionCoverLocation:B

    .line 16
    .line 17
    invoke-static {v7}, Llx0/s;->a(B)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v7

    .line 21
    iget-byte v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->slidePopTopLocation:B

    .line 22
    .line 23
    invoke-static {v8}, Llx0/s;->a(B)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v8

    .line 27
    iget-object v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusSlidePopTop:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 28
    .line 29
    iget-object v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 30
    .line 31
    iget-object v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 32
    .line 33
    iget-object v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 34
    .line 35
    iget-object v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 36
    .line 37
    iget-boolean v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingInternalActive:Z

    .line 38
    .line 39
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isCentralLockingExternalActive:Z

    .line 40
    .line 41
    move/from16 v16, v15

    .line 42
    .line 43
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideFront:Z

    .line 44
    .line 45
    move/from16 v17, v15

    .line 46
    .line 47
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideFront:Z

    .line 48
    .line 49
    move/from16 v18, v15

    .line 50
    .line 51
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenDriverSideRear:Z

    .line 52
    .line 53
    move/from16 v19, v15

    .line 54
    .line 55
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenPassengerSideRear:Z

    .line 56
    .line 57
    move/from16 v20, v15

    .line 58
    .line 59
    iget-boolean v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenTrunk:Z

    .line 60
    .line 61
    iget-boolean v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->isDoorOpenHood:Z

    .line 62
    .line 63
    move/from16 p0, v0

    .line 64
    .line 65
    new-instance v0, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    move/from16 v21, v15

    .line 68
    .line 69
    const-string v15, "C2PNormalPrioManeuverInfoMessageMLB(parkingSideStatus="

    .line 70
    .line 71
    invoke-direct {v0, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ", parkingScenarioStatus="

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", parkingManeuverStatus="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", parkingDirectionStatus="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v1, ", parkingReversibleStatus="

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v1, ", windowStatusMultifunctionCover="

    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", multifunctionCoverLocation="

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    const-string v1, ", slidePopTopLocation="

    .line 123
    .line 124
    const-string v2, ", windowStatusSlidePopTop="

    .line 125
    .line 126
    invoke-static {v0, v7, v1, v8, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v1, ", windowStatusPassengerSideFront="

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v1, ", windowStatusDriverSideFront="

    .line 141
    .line 142
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string v1, ", windowStatusPassengerSideRear="

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const-string v1, ", windowStatusDriverSideRear="

    .line 157
    .line 158
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    const-string v1, ", isCentralLockingInternalActive="

    .line 165
    .line 166
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    const-string v1, ", isCentralLockingExternalActive="

    .line 173
    .line 174
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    const-string v1, ", isDoorOpenDriverSideFront="

    .line 178
    .line 179
    const-string v2, ", isDoorOpenPassengerSideFront="

    .line 180
    .line 181
    move/from16 v3, v16

    .line 182
    .line 183
    move/from16 v4, v17

    .line 184
    .line 185
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 186
    .line 187
    .line 188
    const-string v1, ", isDoorOpenDriverSideRear="

    .line 189
    .line 190
    const-string v2, ", isDoorOpenPassengerSideRear="

    .line 191
    .line 192
    move/from16 v3, v18

    .line 193
    .line 194
    move/from16 v4, v19

    .line 195
    .line 196
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 197
    .line 198
    .line 199
    const-string v1, ", isDoorOpenTrunk="

    .line 200
    .line 201
    const-string v2, ", isDoorOpenHood="

    .line 202
    .line 203
    move/from16 v3, v20

    .line 204
    .line 205
    move/from16 v4, v21

    .line 206
    .line 207
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 208
    .line 209
    .line 210
    const-string v1, ")"

    .line 211
    .line 212
    move/from16 v2, p0

    .line 213
    .line 214
    invoke-static {v0, v2, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    return-object v0
.end method
