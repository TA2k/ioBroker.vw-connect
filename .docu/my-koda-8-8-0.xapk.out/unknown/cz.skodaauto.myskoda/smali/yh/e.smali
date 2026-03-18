.class public final Lyh/e;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lay0/k;

.field public final e:Lyy0/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lgy0/j;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/16 v2, 0x3e8

    .line 5
    .line 6
    invoke-direct {v0, v1, v2, v1}, Lgy0/h;-><init>(III)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/Integer;Lay0/k;)V
    .locals 2

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lyh/e;->d:Lay0/k;

    .line 10
    .line 11
    new-instance p2, Lyh/d;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-direct {p2, v1, v0, p1}, Lyh/d;-><init>(Ljava/lang/String;ZLjava/lang/Integer;)V

    .line 16
    .line 17
    .line 18
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance p2, Lyy0/l1;

    .line 23
    .line 24
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 25
    .line 26
    .line 27
    iput-object p2, p0, Lyh/e;->e:Lyy0/l1;

    .line 28
    .line 29
    return-void
.end method
