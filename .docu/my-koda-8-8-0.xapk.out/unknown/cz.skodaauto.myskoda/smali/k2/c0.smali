.class public abstract Lk2/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk2/l;

.field public static final b:F

.field public static final c:F

.field public static final d:Lk2/l;

.field public static final e:Lk2/p0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lk2/l;->n:Lk2/l;

    .line 2
    .line 3
    sput-object v0, Lk2/c0;->a:Lk2/l;

    .line 4
    .line 5
    const-wide/high16 v1, 0x4008000000000000L    # 3.0

    .line 6
    .line 7
    double-to-float v1, v1

    .line 8
    sput v1, Lk2/c0;->b:F

    .line 9
    .line 10
    sget-object v1, Ls1/f;->a:Ls1/e;

    .line 11
    .line 12
    sget-object v1, Lk2/l;->r:Lk2/l;

    .line 13
    .line 14
    sget v1, Lk2/p;->a:F

    .line 15
    .line 16
    const-wide/high16 v1, 0x4048000000000000L    # 48.0

    .line 17
    .line 18
    double-to-float v1, v1

    .line 19
    sput v1, Lk2/c0;->c:F

    .line 20
    .line 21
    sget-object v1, Lk2/f0;->d:Lk2/f0;

    .line 22
    .line 23
    sput-object v0, Lk2/c0;->d:Lk2/l;

    .line 24
    .line 25
    sget-object v0, Lk2/p0;->k:Lk2/p0;

    .line 26
    .line 27
    sput-object v0, Lk2/c0;->e:Lk2/p0;

    .line 28
    .line 29
    return-void
.end method
