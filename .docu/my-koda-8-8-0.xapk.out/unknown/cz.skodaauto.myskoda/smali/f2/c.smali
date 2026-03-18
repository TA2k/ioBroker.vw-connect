.class public abstract Lf2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/a1;

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    const/16 v1, 0x8

    .line 5
    .line 6
    int-to-float v1, v1

    .line 7
    new-instance v2, Lk1/a1;

    .line 8
    .line 9
    invoke-direct {v2, v0, v1, v0, v1}, Lk1/a1;-><init>(FFFF)V

    .line 10
    .line 11
    .line 12
    sput-object v2, Lf2/c;->a:Lk1/a1;

    .line 13
    .line 14
    const/16 v0, 0x40

    .line 15
    .line 16
    int-to-float v0, v0

    .line 17
    sput v0, Lf2/c;->b:F

    .line 18
    .line 19
    const/16 v0, 0x24

    .line 20
    .line 21
    int-to-float v0, v0

    .line 22
    sput v0, Lf2/c;->c:F

    .line 23
    .line 24
    new-instance v0, Lk1/a1;

    .line 25
    .line 26
    invoke-direct {v0, v1, v1, v1, v1}, Lk1/a1;-><init>(FFFF)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
