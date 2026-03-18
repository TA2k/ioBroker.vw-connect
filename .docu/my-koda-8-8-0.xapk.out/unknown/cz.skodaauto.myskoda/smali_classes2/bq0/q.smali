.class public final Lbq0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbq0/h;

.field public final b:Lzp0/e;

.field public final c:Lkf0/o;

.field public final d:Lsf0/a;


# direct methods
.method public constructor <init>(Lbq0/h;Lzp0/e;Lkf0/o;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbq0/q;->a:Lbq0/h;

    .line 5
    .line 6
    iput-object p2, p0, Lbq0/q;->b:Lzp0/e;

    .line 7
    .line 8
    iput-object p3, p0, Lbq0/q;->c:Lkf0/o;

    .line 9
    .line 10
    iput-object p4, p0, Lbq0/q;->d:Lsf0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lbq0/q;->c:Lkf0/o;

    .line 4
    .line 5
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance p2, La90/c;

    .line 10
    .line 11
    const/16 v0, 0x9

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {p2, v1, p0, v0}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1, p2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iget-object p0, p0, Lbq0/q;->d:Lsf0/a;

    .line 22
    .line 23
    invoke-static {p1, p0, v1}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
