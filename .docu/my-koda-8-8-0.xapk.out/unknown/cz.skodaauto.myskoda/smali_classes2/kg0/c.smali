.class public final Lkg0/c;
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
    iput-object p1, p0, Lkg0/c;->a:Lkg0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Llg0/a;

    .line 4
    .line 5
    iget-wide v3, v0, Llg0/a;->a:J

    .line 6
    .line 7
    iget-object p0, p0, Lkg0/c;->a:Lkg0/b;

    .line 8
    .line 9
    move-object v2, p0

    .line 10
    check-cast v2, Lig0/g;

    .line 11
    .line 12
    iget-object p0, v2, Lig0/g;->d:Lyy0/q1;

    .line 13
    .line 14
    new-instance v0, Llg0/a;

    .line 15
    .line 16
    invoke-direct {v0, v3, v4}, Llg0/a;-><init>(J)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    new-instance v1, Lig0/d;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x1

    .line 26
    invoke-direct/range {v1 .. v6}, Lig0/d;-><init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Lyy0/m1;

    .line 30
    .line 31
    invoke-direct {p0, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    return-object p0
.end method
