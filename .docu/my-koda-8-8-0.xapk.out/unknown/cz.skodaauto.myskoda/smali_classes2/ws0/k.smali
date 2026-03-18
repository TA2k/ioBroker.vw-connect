.class public final Lws0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lws0/f;

.field public final b:Lkf0/b0;

.field public final c:Lkf0/k;

.field public final d:Lkf0/y;

.field public final e:Lws0/l;

.field public final f:Lws0/e;


# direct methods
.method public constructor <init>(Lws0/f;Lkf0/b0;Lkf0/k;Lkf0/y;Lws0/l;Lws0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lws0/k;->a:Lws0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lws0/k;->b:Lkf0/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lws0/k;->c:Lkf0/k;

    .line 9
    .line 10
    iput-object p4, p0, Lws0/k;->d:Lkf0/y;

    .line 11
    .line 12
    iput-object p5, p0, Lws0/k;->e:Lws0/l;

    .line 13
    .line 14
    iput-object p6, p0, Lws0/k;->f:Lws0/e;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lws0/k;->b:Lkf0/b0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-static {v0, v1}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    new-instance v1, Lrz/k;

    .line 15
    .line 16
    const/16 v2, 0x15

    .line 17
    .line 18
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lws/b;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    invoke-direct {v0, v1, v2, p0}, Lws/b;-><init>(Lrz/k;Lkotlin/coroutines/Continuation;Lws0/k;)V

    .line 25
    .line 26
    .line 27
    new-instance p0, Lyy0/m1;

    .line 28
    .line 29
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 30
    .line 31
    .line 32
    return-object p0
.end method
