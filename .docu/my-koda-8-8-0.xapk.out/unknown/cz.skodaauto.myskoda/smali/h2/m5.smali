.class public abstract Lh2/m5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:Lk1/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget v0, Lk2/p;->a:F

    .line 2
    .line 3
    sput v0, Lh2/m5;->a:F

    .line 4
    .line 5
    sget v0, Lk2/v;->b:F

    .line 6
    .line 7
    sput v0, Lh2/m5;->b:F

    .line 8
    .line 9
    sget v0, Lh2/q5;->c:F

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    int-to-float v1, v1

    .line 13
    new-instance v2, Lk1/a1;

    .line 14
    .line 15
    invoke-direct {v2, v0, v1, v0, v1}, Lk1/a1;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    sput-object v2, Lh2/m5;->c:Lk1/a1;

    .line 19
    .line 20
    return-void
.end method
