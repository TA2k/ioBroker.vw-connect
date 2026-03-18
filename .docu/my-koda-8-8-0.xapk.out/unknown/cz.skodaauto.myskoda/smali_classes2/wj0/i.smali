.class public final Lwj0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ltn0/d;

.field public final b:Luj0/d;


# direct methods
.method public constructor <init>(Ltn0/d;Luj0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwj0/i;->a:Ltn0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lwj0/i;->b:Luj0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lwj0/i;->a:Ltn0/d;

    .line 4
    .line 5
    sget-object p2, Lun0/a;->e:Lun0/a;

    .line 6
    .line 7
    invoke-virtual {p1, p2}, Ltn0/d;->a(Lun0/a;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    new-instance p2, Lqa0/a;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    const/16 v1, 0x19

    .line 15
    .line 16
    invoke-direct {p2, v0, p0, v1}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1, p2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
