.class public abstract Lg3/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt4/d;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt4/d;

    .line 2
    .line 3
    const/high16 v1, 0x3f800000    # 1.0f

    .line 4
    .line 5
    invoke-direct {v0, v1, v1}, Lt4/d;-><init>(FF)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lg3/c;->a:Lt4/d;

    .line 9
    .line 10
    return-void
.end method
