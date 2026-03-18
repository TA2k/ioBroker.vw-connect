.class public final Lzo0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lzo0/i;

.field public final c:Lwo0/e;

.field public final d:Lzo0/l;

.field public final e:Lsf0/a;


# direct methods
.method public constructor <init>(Lkf0/o;Lzo0/i;Lwo0/e;Lzo0/l;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzo0/q;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lzo0/q;->b:Lzo0/i;

    .line 7
    .line 8
    iput-object p3, p0, Lzo0/q;->c:Lwo0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lzo0/q;->d:Lzo0/l;

    .line 11
    .line 12
    iput-object p5, p0, Lzo0/q;->e:Lsf0/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lap0/j;)Lam0/i;
    .locals 4

    .line 1
    iget-object v0, p0, Lzo0/q;->d:Lzo0/l;

    .line 2
    .line 3
    check-cast v0, Lwo0/b;

    .line 4
    .line 5
    iget-object v0, v0, Lwo0/b;->b:Lrz/k;

    .line 6
    .line 7
    new-instance v1, Lrz/k;

    .line 8
    .line 9
    const/16 v2, 0x1a

    .line 10
    .line 11
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-static {v1, v0}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v1, Lvh/j;

    .line 20
    .line 21
    const/16 v2, 0xb

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-direct {v1, v2, p0, p1, v3}, Lvh/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v1, v0}, Lyy0/u;->x(Lay0/n;Lyy0/i;)Lyy0/m;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iget-object p0, p0, Lzo0/q;->e:Lsf0/a;

    .line 32
    .line 33
    invoke-static {p1, p0, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lap0/j;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lzo0/q;->a(Lap0/j;)Lam0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
