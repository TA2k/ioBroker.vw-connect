.class public final Lbp/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static b:Ljava/lang/ref/WeakReference;


# instance fields
.field public final a:Lbp/q;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lbp/q;

    .line 5
    .line 6
    sget-object v5, Lko/h;->c:Lko/h;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    sget-object v3, Lbp/m;->a:Lc2/k;

    .line 10
    .line 11
    sget-object v4, Lko/b;->a:Lko/a;

    .line 12
    .line 13
    move-object v1, p1

    .line 14
    invoke-direct/range {v0 .. v5}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lbp/b;->a:Lbp/q;

    .line 18
    .line 19
    return-void
.end method
