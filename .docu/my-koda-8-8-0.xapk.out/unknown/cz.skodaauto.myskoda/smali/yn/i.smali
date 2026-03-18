.class public final Lyn/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltn/b;


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyn/i;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Lyn/i;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Lz5/e;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lyn/i;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lq/q;

    .line 4
    .line 5
    iget-object p0, p0, Lyn/i;->d:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lj1/a;

    .line 8
    .line 9
    iget v1, p1, Lz5/e;->b:I

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    iget-object p1, p1, Lz5/e;->a:Landroid/graphics/Typeface;

    .line 14
    .line 15
    new-instance v1, Llr/b;

    .line 16
    .line 17
    const/16 v2, 0x1a

    .line 18
    .line 19
    invoke-direct {v1, v2, p0, p1}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lq/q;->execute(Ljava/lang/Runnable;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    new-instance p1, Lcom/google/android/material/datepicker/n;

    .line 27
    .line 28
    const/4 v2, 0x4

    .line 29
    invoke-direct {p1, p0, v1, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, p1}, Lq/q;->execute(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public get()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v1, La61/a;

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    invoke-direct {v1, v0}, La61/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v2, Lwq/f;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-direct {v2, v0}, Lwq/f;-><init>(I)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lyn/i;->d:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lkx0/a;

    .line 16
    .line 17
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object p0, p0, Lyn/i;->e:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v5, p0

    .line 24
    check-cast v5, Lkx0/a;

    .line 25
    .line 26
    move-object p0, v0

    .line 27
    new-instance v0, Lyn/h;

    .line 28
    .line 29
    move-object v4, p0

    .line 30
    check-cast v4, Lyn/k;

    .line 31
    .line 32
    sget-object v3, Lyn/a;->f:Lyn/a;

    .line 33
    .line 34
    invoke-direct/range {v0 .. v5}, Lyn/h;-><init>(Lao/a;Lao/a;Lyn/a;Lyn/k;Lkx0/a;)V

    .line 35
    .line 36
    .line 37
    return-object v0
.end method
