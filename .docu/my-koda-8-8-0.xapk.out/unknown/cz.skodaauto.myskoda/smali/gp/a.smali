.class public final Lgp/a;
.super Lko/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Lc2/k;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lko/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lc2/k;

    .line 7
    .line 8
    new-instance v2, Lbp/l;

    .line 9
    .line 10
    const/4 v3, 0x3

    .line 11
    invoke-direct {v2, v3}, Lbp/l;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const-string v3, "LocationServices.API"

    .line 15
    .line 16
    invoke-direct {v1, v3, v2, v0}, Lc2/k;-><init>(Ljava/lang/String;Llp/wd;Lko/d;)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lgp/a;->n:Lc2/k;

    .line 20
    .line 21
    return-void
.end method
