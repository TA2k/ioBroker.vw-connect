.class public final enum Lau/i;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lau/i;

.field public static final enum f:Lau/i;

.field public static final enum g:Lau/i;

.field public static final enum h:Lau/i;

.field public static final synthetic i:[Lau/i;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lau/i;

    .line 2
    .line 3
    const-string v1, "APPLICATION_PROCESS_STATE_UNKNOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lau/i;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lau/i;->e:Lau/i;

    .line 10
    .line 11
    new-instance v1, Lau/i;

    .line 12
    .line 13
    const-string v2, "FOREGROUND"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3, v3}, Lau/i;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lau/i;->f:Lau/i;

    .line 20
    .line 21
    new-instance v2, Lau/i;

    .line 22
    .line 23
    const-string v3, "BACKGROUND"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4, v4}, Lau/i;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lau/i;->g:Lau/i;

    .line 30
    .line 31
    new-instance v3, Lau/i;

    .line 32
    .line 33
    const-string v4, "FOREGROUND_BACKGROUND"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5, v5}, Lau/i;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lau/i;->h:Lau/i;

    .line 40
    .line 41
    filled-new-array {v0, v1, v2, v3}, [Lau/i;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lau/i;->i:[Lau/i;

    .line 46
    .line 47
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lau/i;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lau/i;
    .locals 1

    .line 1
    const-class v0, Lau/i;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lau/i;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lau/i;
    .locals 1

    .line 1
    sget-object v0, Lau/i;->i:[Lau/i;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lau/i;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lau/i;

    .line 8
    .line 9
    return-object v0
.end method
