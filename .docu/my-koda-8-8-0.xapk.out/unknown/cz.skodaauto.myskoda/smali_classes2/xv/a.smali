.class public final Lxv/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/k;

.field public final b:Lt2/b;


# direct methods
.method public constructor <init>(Lt2/b;I)V
    .locals 1

    .line 1
    sget-object v0, Ltv/c;->i:Ltv/c;

    .line 2
    .line 3
    and-int/lit8 p2, p2, 0x1

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    :cond_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lxv/a;->a:Lay0/k;

    .line 12
    .line 13
    iput-object p1, p0, Lxv/a;->b:Lt2/b;

    .line 14
    .line 15
    return-void
.end method
