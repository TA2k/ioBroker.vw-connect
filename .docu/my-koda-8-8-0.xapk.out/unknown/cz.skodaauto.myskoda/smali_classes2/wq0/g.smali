.class public final Lwq0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwq0/a;


# direct methods
.method public constructor <init>(Lwq0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/g;->a:Lwq0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lwq0/g;->a:Lwq0/a;

    .line 4
    .line 5
    check-cast p0, Luq0/a;

    .line 6
    .line 7
    iget-object p1, p0, Luq0/a;->c:Lyy0/q1;

    .line 8
    .line 9
    invoke-virtual {p1}, Lyy0/q1;->q()V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Luq0/a;->a:Lyy0/q1;

    .line 13
    .line 14
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    invoke-static {p1, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
