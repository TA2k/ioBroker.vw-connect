.class public final Lkg0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkg0/b;


# direct methods
.method public constructor <init>(Lkg0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkg0/d;->a:Lkg0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(J)Lyy0/m1;
    .locals 6

    .line 1
    iget-object p0, p0, Lkg0/d;->a:Lkg0/b;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Lig0/g;

    .line 5
    .line 6
    iget-object p0, v1, Lig0/g;->g:Lyy0/q1;

    .line 7
    .line 8
    new-instance v0, Llg0/a;

    .line 9
    .line 10
    invoke-direct {v0, p1, p2}, Llg0/a;-><init>(J)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    new-instance v0, Lig0/d;

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x2

    .line 20
    move-wide v2, p1

    .line 21
    invoke-direct/range {v0 .. v5}, Lig0/d;-><init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    new-instance p0, Lyy0/m1;

    .line 25
    .line 26
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    return-object p0
.end method

.method public final synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Llg0/a;

    .line 4
    .line 5
    iget-wide v0, v0, Llg0/a;->a:J

    .line 6
    .line 7
    invoke-virtual {p0, v0, v1}, Lkg0/d;->a(J)Lyy0/m1;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
