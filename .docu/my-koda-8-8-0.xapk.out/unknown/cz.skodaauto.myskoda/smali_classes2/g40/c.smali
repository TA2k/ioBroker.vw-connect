.class public final enum Lg40/c;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lg40/c;

.field public static final enum e:Lg40/c;

.field public static final enum f:Lg40/c;

.field public static final enum g:Lg40/c;

.field public static final synthetic h:[Lg40/c;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lg40/c;

    .line 2
    .line 3
    const-string v1, "OpenCoupons"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lg40/c;->d:Lg40/c;

    .line 10
    .line 11
    new-instance v1, Lg40/c;

    .line 12
    .line 13
    const-string v2, "OpenConsents"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lg40/c;->e:Lg40/c;

    .line 20
    .line 21
    new-instance v2, Lg40/c;

    .line 22
    .line 23
    const-string v3, "OpenRegistration"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lg40/c;->f:Lg40/c;

    .line 30
    .line 31
    new-instance v3, Lg40/c;

    .line 32
    .line 33
    const-string v4, "ShowVouchersApplyDisabledDialog"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lg40/c;->g:Lg40/c;

    .line 40
    .line 41
    filled-new-array {v0, v1, v2, v3}, [Lg40/c;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lg40/c;->h:[Lg40/c;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lg40/c;
    .locals 1

    .line 1
    const-class v0, Lg40/c;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lg40/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lg40/c;
    .locals 1

    .line 1
    sget-object v0, Lg40/c;->h:[Lg40/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lg40/c;

    .line 8
    .line 9
    return-object v0
.end method
