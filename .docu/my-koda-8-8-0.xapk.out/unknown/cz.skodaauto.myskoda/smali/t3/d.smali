.class public abstract Lt3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt3/o;

.field public static final b:Lt3/o;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt3/o;

    .line 2
    .line 3
    sget-object v1, Lt3/b;->d:Lt3/b;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lt3/a;-><init>(Lay0/n;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lt3/d;->a:Lt3/o;

    .line 9
    .line 10
    new-instance v0, Lt3/o;

    .line 11
    .line 12
    sget-object v1, Lt3/c;->d:Lt3/c;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lt3/a;-><init>(Lay0/n;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lt3/d;->b:Lt3/o;

    .line 18
    .line 19
    return-void
.end method
