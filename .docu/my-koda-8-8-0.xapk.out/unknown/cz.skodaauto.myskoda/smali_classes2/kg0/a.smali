.class public final Lkg0/a;
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
    iput-object p1, p0, Lkg0/a;->a:Lkg0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Llg0/c;)Lyy0/m1;
    .locals 6

    .line 1
    iget-object p0, p0, Lkg0/a;->a:Lkg0/b;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Lig0/g;

    .line 5
    .line 6
    new-instance p0, Ljava/security/SecureRandom;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/security/SecureRandom;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/Random;->nextLong()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    iget-object p0, v1, Lig0/g;->a:Lyy0/q1;

    .line 16
    .line 17
    new-instance v0, Llg0/e;

    .line 18
    .line 19
    invoke-direct {v0, v2, v3, p1}, Llg0/e;-><init>(JLlg0/c;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    new-instance v0, Lig0/d;

    .line 26
    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v0 .. v5}, Lig0/d;-><init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    new-instance p0, Lyy0/m1;

    .line 33
    .line 34
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Llg0/c;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lkg0/a;->a(Llg0/c;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
