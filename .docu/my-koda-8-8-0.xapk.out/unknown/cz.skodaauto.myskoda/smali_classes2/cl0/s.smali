.class public final Lcl0/s;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lal0/i1;

.field public final i:Lij0/a;

.field public j:Lbl0/h0;


# direct methods
.method public constructor <init>(Lal0/x0;Lal0/q0;Lal0/i1;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Lcl0/r;

    .line 2
    .line 3
    invoke-direct {v0}, Lcl0/r;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p3, p0, Lcl0/s;->h:Lal0/i1;

    .line 10
    .line 11
    iput-object p4, p0, Lcl0/s;->i:Lij0/a;

    .line 12
    .line 13
    new-instance v1, La7/o;

    .line 14
    .line 15
    const/16 v2, 0x19

    .line 16
    .line 17
    const/4 v6, 0x0

    .line 18
    move-object v4, p0

    .line 19
    move-object v3, p1

    .line 20
    move-object v5, p2

    .line 21
    invoke-direct/range {v1 .. v6}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v4, v1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
