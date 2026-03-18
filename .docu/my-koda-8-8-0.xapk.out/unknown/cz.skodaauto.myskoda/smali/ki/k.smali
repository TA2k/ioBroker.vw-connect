.class public final enum Lki/k;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lki/k;

.field public static final enum e:Lki/k;

.field public static final enum f:Lki/k;

.field public static final enum g:Lki/k;

.field public static final synthetic h:[Lki/k;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lki/k;

    .line 2
    .line 3
    const-string v1, "Development"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lki/k;->d:Lki/k;

    .line 10
    .line 11
    new-instance v1, Lki/k;

    .line 12
    .line 13
    const-string v2, "Test"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lki/k;

    .line 20
    .line 21
    const-string v3, "Staging"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lki/k;->e:Lki/k;

    .line 28
    .line 29
    new-instance v3, Lki/k;

    .line 30
    .line 31
    const-string v4, "Production"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Lki/k;->f:Lki/k;

    .line 38
    .line 39
    new-instance v4, Lki/k;

    .line 40
    .line 41
    const-string v5, "Mock"

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    sput-object v4, Lki/k;->g:Lki/k;

    .line 48
    .line 49
    new-instance v5, Lki/k;

    .line 50
    .line 51
    const-string v6, "Local"

    .line 52
    .line 53
    const/4 v7, 0x5

    .line 54
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 55
    .line 56
    .line 57
    new-instance v6, Lki/k;

    .line 58
    .line 59
    const-string v7, "LocalMock"

    .line 60
    .line 61
    const/4 v8, 0x6

    .line 62
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 63
    .line 64
    .line 65
    filled-new-array/range {v0 .. v6}, [Lki/k;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    sput-object v0, Lki/k;->h:[Lki/k;

    .line 70
    .line 71
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lki/k;
    .locals 1

    .line 1
    const-class v0, Lki/k;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lki/k;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lki/k;
    .locals 1

    .line 1
    sget-object v0, Lki/k;->h:[Lki/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lki/k;

    .line 8
    .line 9
    return-object v0
.end method
