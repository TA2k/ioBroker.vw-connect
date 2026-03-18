.class public final enum Li91/o0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Li91/o0;

.field public static final enum f:Li91/o0;

.field public static final synthetic g:[Li91/o0;


# instance fields
.field public final d:F


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Li91/o0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/high16 v2, -0x40800000    # -1.0f

    .line 5
    .line 6
    const-string v3, "Start"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Li91/o0;-><init>(Ljava/lang/String;IF)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Li91/o0;->e:Li91/o0;

    .line 12
    .line 13
    new-instance v1, Li91/o0;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const/high16 v3, 0x3f800000    # 1.0f

    .line 17
    .line 18
    const-string v4, "End"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Li91/o0;-><init>(Ljava/lang/String;IF)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Li91/o0;->f:Li91/o0;

    .line 24
    .line 25
    filled-new-array {v0, v1}, [Li91/o0;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Li91/o0;->g:[Li91/o0;

    .line 30
    .line 31
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IF)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Li91/o0;->d:F

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Li91/o0;
    .locals 1

    .line 1
    const-class v0, Li91/o0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li91/o0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Li91/o0;
    .locals 1

    .line 1
    sget-object v0, Li91/o0;->g:[Li91/o0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Li91/o0;

    .line 8
    .line 9
    return-object v0
.end method
