.class public abstract Lf2/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget v0, Lf2/d0;->c:F

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    int-to-float v1, v1

    .line 5
    new-instance v2, Lk1/a1;

    .line 6
    .line 7
    invoke-direct {v2, v0, v1, v0, v1}, Lk1/a1;-><init>(FFFF)V

    .line 8
    .line 9
    .line 10
    sput-object v2, Lf2/a0;->a:Lk1/a1;

    .line 11
    .line 12
    return-void
.end method
