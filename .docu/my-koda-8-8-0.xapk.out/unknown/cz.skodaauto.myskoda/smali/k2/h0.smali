.class public abstract Lk2/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk2/f0;

.field public static final b:Lk2/l;

.field public static final c:F

.field public static final d:F

.field public static final e:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lk2/l;->v:Lk2/l;

    .line 2
    .line 3
    sget-object v0, Lk2/f0;->e:Lk2/f0;

    .line 4
    .line 5
    sput-object v0, Lk2/h0;->a:Lk2/f0;

    .line 6
    .line 7
    sget-object v0, Lk2/l;->k:Lk2/l;

    .line 8
    .line 9
    sput-object v0, Lk2/h0;->b:Lk2/l;

    .line 10
    .line 11
    const-wide/high16 v0, 0x4010000000000000L    # 4.0

    .line 12
    .line 13
    double-to-float v0, v0

    .line 14
    sput v0, Lk2/h0;->c:F

    .line 15
    .line 16
    const-wide/high16 v0, 0x4040000000000000L    # 32.0

    .line 17
    .line 18
    double-to-float v0, v0

    .line 19
    sput v0, Lk2/h0;->d:F

    .line 20
    .line 21
    sget v0, Lk2/p;->b:F

    .line 22
    .line 23
    sput v0, Lk2/h0;->e:F

    .line 24
    .line 25
    return-void
.end method
