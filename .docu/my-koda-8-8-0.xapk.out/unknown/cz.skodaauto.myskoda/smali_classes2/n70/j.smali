.class public final synthetic Ln70/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lm70/p;

.field public final synthetic e:Lxj0/j;

.field public final synthetic f:Li91/r2;

.field public final synthetic g:F

.field public final synthetic h:Ll2/b1;

.field public final synthetic i:Lk1/z0;

.field public final synthetic j:Lm70/r;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lm70/p;Lxj0/j;Li91/r2;FLl2/b1;Lk1/z0;Lm70/r;Lay0/a;Lay0/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln70/j;->d:Lm70/p;

    .line 5
    .line 6
    iput-object p2, p0, Ln70/j;->e:Lxj0/j;

    .line 7
    .line 8
    iput-object p3, p0, Ln70/j;->f:Li91/r2;

    .line 9
    .line 10
    iput p4, p0, Ln70/j;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Ln70/j;->h:Ll2/b1;

    .line 13
    .line 14
    iput-object p6, p0, Ln70/j;->i:Lk1/z0;

    .line 15
    .line 16
    iput-object p7, p0, Ln70/j;->j:Lm70/r;

    .line 17
    .line 18
    iput-object p8, p0, Ln70/j;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Ln70/j;->l:Lay0/k;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object v9, p1

    .line 2
    check-cast v9, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/16 p1, 0x6e01

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v10

    .line 15
    iget-object v0, p0, Ln70/j;->d:Lm70/p;

    .line 16
    .line 17
    iget-object v1, p0, Ln70/j;->e:Lxj0/j;

    .line 18
    .line 19
    iget-object v2, p0, Ln70/j;->f:Li91/r2;

    .line 20
    .line 21
    iget v3, p0, Ln70/j;->g:F

    .line 22
    .line 23
    iget-object v4, p0, Ln70/j;->h:Ll2/b1;

    .line 24
    .line 25
    iget-object v5, p0, Ln70/j;->i:Lk1/z0;

    .line 26
    .line 27
    iget-object v6, p0, Ln70/j;->j:Lm70/r;

    .line 28
    .line 29
    iget-object v7, p0, Ln70/j;->k:Lay0/a;

    .line 30
    .line 31
    iget-object v8, p0, Ln70/j;->l:Lay0/k;

    .line 32
    .line 33
    invoke-static/range {v0 .. v10}, Ln70/m;->d(Lm70/p;Lxj0/j;Li91/r2;FLl2/b1;Lk1/z0;Lm70/r;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
