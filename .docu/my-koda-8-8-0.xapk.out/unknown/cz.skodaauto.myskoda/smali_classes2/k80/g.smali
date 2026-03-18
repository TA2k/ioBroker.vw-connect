.class public final Lk80/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lk80/b;

.field public final c:Lbd0/c;


# direct methods
.method public constructor <init>(Lkf0/b0;Lk80/b;Lbd0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk80/g;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lk80/g;->b:Lk80/b;

    .line 7
    .line 8
    iput-object p3, p0, Lk80/g;->c:Lbd0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lk80/g;->a:Lkf0/b0;

    .line 4
    .line 5
    invoke-virtual {p1}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    new-instance p2, Lk31/t;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/4 v1, 0x7

    .line 15
    invoke-direct {p2, p0, v0, v1}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {p2, p1}, Lyy0/u;->x(Lay0/n;Lyy0/i;)Lyy0/m;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance p2, Lac/l;

    .line 23
    .line 24
    const/16 v0, 0x15

    .line 25
    .line 26
    invoke-direct {p2, v0, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-object p2
.end method
