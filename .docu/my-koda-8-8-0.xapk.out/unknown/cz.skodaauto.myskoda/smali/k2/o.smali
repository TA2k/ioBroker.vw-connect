.class public abstract Lk2/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk2/l;

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lk2/l;->m:Lk2/l;

    .line 2
    .line 3
    sput-object v0, Lk2/o;->a:Lk2/l;

    .line 4
    .line 5
    const-wide/high16 v0, 0x3ff0000000000000L    # 1.0

    .line 6
    .line 7
    double-to-float v0, v0

    .line 8
    sput v0, Lk2/o;->b:F

    .line 9
    .line 10
    return-void
.end method
