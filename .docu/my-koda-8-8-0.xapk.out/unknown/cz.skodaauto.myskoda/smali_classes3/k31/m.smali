.class public final Lk31/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lf31/f;

.field public final b:Lvy0/x;


# direct methods
.method public constructor <init>(Lf31/f;)V
    .locals 2

    .line 1
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 2
    .line 3
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 4
    .line 5
    const-string v1, "dispatcherIO"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lk31/m;->a:Lf31/f;

    .line 14
    .line 15
    iput-object v0, p0, Lk31/m;->b:Lvy0/x;

    .line 16
    .line 17
    return-void
.end method
