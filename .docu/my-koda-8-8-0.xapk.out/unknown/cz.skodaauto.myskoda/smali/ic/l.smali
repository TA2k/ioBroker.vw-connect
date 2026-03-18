.class public final enum Lic/l;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lic/l;

.field public static final enum f:Lic/l;

.field public static final synthetic g:[Lic/l;


# instance fields
.field public final d:Ldc/e;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lic/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Ldc/e;->f:Ldc/e;

    .line 5
    .line 6
    const-string v3, "RemindMeLater"

    .line 7
    .line 8
    invoke-direct {v0, v1, v2, v3}, Lic/l;-><init>(ILdc/e;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lic/l;->e:Lic/l;

    .line 12
    .line 13
    new-instance v1, Lic/l;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const/4 v3, 0x0

    .line 17
    const-string v4, "None"

    .line 18
    .line 19
    invoke-direct {v1, v2, v3, v4}, Lic/l;-><init>(ILdc/e;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    sput-object v1, Lic/l;->f:Lic/l;

    .line 23
    .line 24
    filled-new-array {v0, v1}, [Lic/l;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sput-object v0, Lic/l;->g:[Lic/l;

    .line 29
    .line 30
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public constructor <init>(ILdc/e;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p3, p1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lic/l;->d:Ldc/e;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lic/l;
    .locals 1

    .line 1
    const-class v0, Lic/l;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lic/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lic/l;
    .locals 1

    .line 1
    sget-object v0, Lic/l;->g:[Lic/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lic/l;

    .line 8
    .line 9
    return-object v0
.end method
