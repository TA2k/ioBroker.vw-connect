.class public final Ltw0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:Lam0/i;

.field public final synthetic e:Low0/e;

.field public final synthetic f:Ljava/nio/charset/Charset;

.field public final synthetic g:Lzw0/a;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lam0/i;Low0/e;Ljava/nio/charset/Charset;Lzw0/a;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltw0/f;->d:Lam0/i;

    .line 5
    .line 6
    iput-object p2, p0, Ltw0/f;->e:Low0/e;

    .line 7
    .line 8
    iput-object p3, p0, Ltw0/f;->f:Ljava/nio/charset/Charset;

    .line 9
    .line 10
    iput-object p4, p0, Ltw0/f;->g:Lzw0/a;

    .line 11
    .line 12
    iput-object p5, p0, Ltw0/f;->h:Ljava/lang/Object;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Ltw0/e;

    .line 2
    .line 3
    iget-object v4, p0, Ltw0/f;->g:Lzw0/a;

    .line 4
    .line 5
    iget-object v5, p0, Ltw0/f;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v2, p0, Ltw0/f;->e:Low0/e;

    .line 8
    .line 9
    iget-object v3, p0, Ltw0/f;->f:Ljava/nio/charset/Charset;

    .line 10
    .line 11
    move-object v1, p1

    .line 12
    invoke-direct/range {v0 .. v5}, Ltw0/e;-><init>(Lyy0/j;Low0/e;Ljava/nio/charset/Charset;Lzw0/a;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Ltw0/f;->d:Lam0/i;

    .line 16
    .line 17
    invoke-virtual {p0, v0, p2}, Lam0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    if-ne p0, p1, :cond_0

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method
