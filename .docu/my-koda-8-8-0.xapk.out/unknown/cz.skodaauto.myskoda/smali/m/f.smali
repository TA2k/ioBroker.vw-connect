.class public final Lm/f;
.super Ll/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic l:I

.field public final synthetic m:Lm/j;


# direct methods
.method public constructor <init>(Lm/j;Landroid/content/Context;Ll/d0;Landroid/view/View;)V
    .locals 8

    const/4 v0, 0x0

    iput v0, p0, Lm/f;->l:I

    .line 8
    iput-object p1, p0, Lm/f;->m:Lm/j;

    const v6, 0x7f040023

    const/4 v7, 0x0

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    .line 9
    invoke-direct/range {v1 .. v7}, Ll/v;-><init>(Landroid/content/Context;Ll/l;Landroid/view/View;ZII)V

    .line 10
    iget-object p0, v3, Ll/d0;->A:Ll/n;

    .line 11
    iget p0, p0, Ll/n;->x:I

    const/16 p2, 0x20

    and-int/2addr p0, p2

    if-ne p0, p2, :cond_0

    goto :goto_0

    .line 12
    :cond_0
    iget-object p0, p1, Lm/j;->l:Lm/i;

    if-nez p0, :cond_1

    .line 13
    iget-object p0, p1, Lm/j;->k:Ll/z;

    .line 14
    check-cast p0, Landroid/view/View;

    .line 15
    :cond_1
    iput-object p0, v1, Ll/v;->e:Landroid/view/View;

    .line 16
    :goto_0
    iget-object p0, p1, Lm/j;->z:Lj1/a;

    .line 17
    iput-object p0, v1, Ll/v;->h:Ll/w;

    .line 18
    iget-object p1, v1, Ll/v;->i:Ll/t;

    if-eqz p1, :cond_2

    .line 19
    invoke-interface {p1, p0}, Ll/x;->e(Ll/w;)V

    :cond_2
    return-void
.end method

.method public constructor <init>(Lm/j;Landroid/content/Context;Ll/l;Landroid/view/View;)V
    .locals 8

    const/4 v0, 0x1

    iput v0, p0, Lm/f;->l:I

    .line 1
    iput-object p1, p0, Lm/f;->m:Lm/j;

    const v6, 0x7f040023

    const/4 v7, 0x0

    const/4 v5, 0x1

    move-object v1, p0

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    .line 2
    invoke-direct/range {v1 .. v7}, Ll/v;-><init>(Landroid/content/Context;Ll/l;Landroid/view/View;ZII)V

    const p0, 0x800005

    .line 3
    iput p0, v1, Ll/v;->f:I

    .line 4
    iget-object p0, p1, Lm/j;->z:Lj1/a;

    .line 5
    iput-object p0, v1, Ll/v;->h:Ll/w;

    .line 6
    iget-object p1, v1, Ll/v;->i:Ll/t;

    if-eqz p1, :cond_0

    .line 7
    invoke-interface {p1, p0}, Ll/x;->e(Ll/w;)V

    :cond_0
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 3

    .line 1
    iget v0, p0, Lm/f;->l:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lm/f;->m:Lm/j;

    .line 7
    .line 8
    iget-object v1, v0, Lm/j;->f:Ll/l;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-virtual {v1, v2}, Ll/l;->c(Z)V

    .line 14
    .line 15
    .line 16
    :cond_0
    const/4 v1, 0x0

    .line 17
    iput-object v1, v0, Lm/j;->v:Lm/f;

    .line 18
    .line 19
    invoke-super {p0}, Ll/v;->c()V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    const/4 v0, 0x0

    .line 24
    iget-object v1, p0, Lm/f;->m:Lm/j;

    .line 25
    .line 26
    iput-object v0, v1, Lm/j;->w:Lm/f;

    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-super {p0}, Ll/v;->c()V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
