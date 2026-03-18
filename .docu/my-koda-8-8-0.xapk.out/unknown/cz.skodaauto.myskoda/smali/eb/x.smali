.class public final enum Leb/x;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Leb/x;

.field public static final enum e:Leb/x;

.field public static final enum f:Leb/x;

.field public static final enum g:Leb/x;

.field public static final enum h:Leb/x;

.field public static final enum i:Leb/x;

.field public static final synthetic j:[Leb/x;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Leb/x;

    .line 2
    .line 3
    const-string v1, "NOT_REQUIRED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Leb/x;->d:Leb/x;

    .line 10
    .line 11
    new-instance v1, Leb/x;

    .line 12
    .line 13
    const-string v2, "CONNECTED"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Leb/x;->e:Leb/x;

    .line 20
    .line 21
    new-instance v2, Leb/x;

    .line 22
    .line 23
    const-string v3, "UNMETERED"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Leb/x;->f:Leb/x;

    .line 30
    .line 31
    new-instance v3, Leb/x;

    .line 32
    .line 33
    const-string v4, "NOT_ROAMING"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Leb/x;->g:Leb/x;

    .line 40
    .line 41
    new-instance v4, Leb/x;

    .line 42
    .line 43
    const-string v5, "METERED"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Leb/x;->h:Leb/x;

    .line 50
    .line 51
    new-instance v5, Leb/x;

    .line 52
    .line 53
    const-string v6, "TEMPORARILY_UNMETERED"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Leb/x;->i:Leb/x;

    .line 60
    .line 61
    filled-new-array/range {v0 .. v5}, [Leb/x;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Leb/x;->j:[Leb/x;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Leb/x;
    .locals 1

    .line 1
    const-class v0, Leb/x;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Leb/x;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Leb/x;
    .locals 1

    .line 1
    sget-object v0, Leb/x;->j:[Leb/x;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Leb/x;

    .line 8
    .line 9
    return-object v0
.end method
