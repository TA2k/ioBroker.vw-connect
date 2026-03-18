.class public abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u0000 \u000b2\u00020\u0001:\u0004\u0008\t\n\u000bB\u0011\u0008\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0014\u0010\u0002\u001a\u00020\u0003X\u0080\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\u0082\u0001\u0003\u000c\r\u000e\u00a8\u0006\u000f"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "",
        "originalValue",
        "",
        "<init>",
        "(I)V",
        "getOriginalValue$remoteparkassistcoremeb_release",
        "()I",
        "Invalid",
        "Closed",
        "Open",
        "Companion",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;",
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
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;

.field private static final WINDOW_STATE_CLOSED_PERCENTAGE:F = 0.0f

.field private static final WINDOW_STATE_COMPLETELY_OPEN_VALUE:I = 0xc8

.field private static final WINDOW_STATE_OPEN_PERCENTAGE:F = 1.0f


# instance fields
.field private final originalValue:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(I)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->originalValue:I

    return-void
.end method

.method public synthetic constructor <init>(ILkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final getOriginalValue$remoteparkassistcoremeb_release()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->originalValue:I

    .line 2
    .line 3
    return p0
.end method
