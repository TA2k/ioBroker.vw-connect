.class public final Lxm0/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lvm0/c;

.field public final i:Lvm0/e;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lvm0/c;Lvm0/e;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lxm0/b;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1, v2}, Lxm0/b;-><init>(Lwm0/b;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lxm0/c;->h:Lvm0/c;

    .line 13
    .line 14
    iput-object p2, p0, Lxm0/c;->i:Lvm0/e;

    .line 15
    .line 16
    iput-object p3, p0, Lxm0/c;->j:Lij0/a;

    .line 17
    .line 18
    new-instance p1, Lvo0/e;

    .line 19
    .line 20
    const/16 p2, 0x19

    .line 21
    .line 22
    invoke-direct {p1, p0, v2, p2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
