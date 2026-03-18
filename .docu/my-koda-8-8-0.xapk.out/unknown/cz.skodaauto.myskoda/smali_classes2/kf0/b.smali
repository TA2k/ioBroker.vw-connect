.class public final Lkf0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lif0/u;

.field public final b:Lif0/f0;


# direct methods
.method public constructor <init>(Lif0/u;Lif0/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/b;->a:Lif0/u;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/b;->b:Lif0/f0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lss0/j0;

    .line 2
    .line 3
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p2, p0, Lkf0/b;->a:Lif0/u;

    .line 6
    .line 7
    invoke-virtual {p2, p1}, Lif0/u;->a(Ljava/lang/String;)Llb0/y;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    new-instance p2, Lk31/t;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/16 v1, 0x9

    .line 15
    .line 16
    invoke-direct {p2, p0, v0, v1}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p2, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
