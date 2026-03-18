.class public final enum Lyq0/w;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lip/v;

.field public static final enum f:Lyq0/w;

.field public static final enum g:Lyq0/w;

.field public static final enum h:Lyq0/w;

.field public static final synthetic i:[Lyq0/w;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lyq0/w;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "CORRECT_SPIN"

    .line 5
    .line 6
    const-string v3, "CorrectSpin"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lyq0/w;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lyq0/w;->f:Lyq0/w;

    .line 12
    .line 13
    new-instance v1, Lyq0/w;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "INCORRECT_SPIN"

    .line 17
    .line 18
    const-string v4, "IncorrectSpin"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lyq0/w;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lyq0/w;

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    const-string v4, "LOCKED_SPIN"

    .line 27
    .line 28
    const-string v5, "LockedSpin"

    .line 29
    .line 30
    invoke-direct {v2, v5, v3, v4}, Lyq0/w;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sput-object v2, Lyq0/w;->g:Lyq0/w;

    .line 34
    .line 35
    new-instance v3, Lyq0/w;

    .line 36
    .line 37
    const/4 v4, 0x3

    .line 38
    const-string v5, "UNKNOWN"

    .line 39
    .line 40
    const-string v6, "Unknown"

    .line 41
    .line 42
    invoke-direct {v3, v6, v4, v5}, Lyq0/w;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sput-object v3, Lyq0/w;->h:Lyq0/w;

    .line 46
    .line 47
    filled-new-array {v0, v1, v2, v3}, [Lyq0/w;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lyq0/w;->i:[Lyq0/w;

    .line 52
    .line 53
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 54
    .line 55
    .line 56
    new-instance v0, Lip/v;

    .line 57
    .line 58
    const/16 v1, 0x1b

    .line 59
    .line 60
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Lyq0/w;->e:Lip/v;

    .line 64
    .line 65
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lyq0/w;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lyq0/w;
    .locals 1

    .line 1
    const-class v0, Lyq0/w;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lyq0/w;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lyq0/w;
    .locals 1

    .line 1
    sget-object v0, Lyq0/w;->i:[Lyq0/w;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lyq0/w;

    .line 8
    .line 9
    return-object v0
.end method
