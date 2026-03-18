.class public final Lvy0/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpx0/f;


# instance fields
.field public final d:Lay0/k;

.field public final e:Lpx0/f;


# direct methods
.method public constructor <init>(Lpx0/f;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "baseKey"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lvy0/w;->d:Lay0/k;

    .line 10
    .line 11
    instance-of p2, p1, Lvy0/w;

    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    check-cast p1, Lvy0/w;

    .line 16
    .line 17
    iget-object p1, p1, Lvy0/w;->e:Lpx0/f;

    .line 18
    .line 19
    :cond_0
    iput-object p1, p0, Lvy0/w;->e:Lpx0/f;

    .line 20
    .line 21
    return-void
.end method
