.class public final enum Lvp/p2;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lvp/p2;

.field public static final enum f:Lvp/p2;

.field public static final enum g:Lvp/p2;

.field public static final enum h:Lvp/p2;

.field public static final synthetic i:[Lvp/p2;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lvp/p2;

    .line 2
    .line 3
    const-string v1, "UNKNOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lvp/p2;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lvp/p2;->e:Lvp/p2;

    .line 10
    .line 11
    new-instance v1, Lvp/p2;

    .line 12
    .line 13
    const-string v2, "SUCCESS"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3, v3}, Lvp/p2;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lvp/p2;->f:Lvp/p2;

    .line 20
    .line 21
    new-instance v2, Lvp/p2;

    .line 22
    .line 23
    const-string v3, "FAILURE"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4, v4}, Lvp/p2;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lvp/p2;->g:Lvp/p2;

    .line 30
    .line 31
    new-instance v3, Lvp/p2;

    .line 32
    .line 33
    const-string v4, "BACKOFF"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5, v5}, Lvp/p2;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lvp/p2;->h:Lvp/p2;

    .line 40
    .line 41
    filled-new-array {v0, v1, v2, v3}, [Lvp/p2;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lvp/p2;->i:[Lvp/p2;

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
    iput p3, p0, Lvp/p2;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static values()[Lvp/p2;
    .locals 1

    .line 1
    sget-object v0, Lvp/p2;->i:[Lvp/p2;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lvp/p2;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lvp/p2;

    .line 8
    .line 9
    return-object v0
.end method
