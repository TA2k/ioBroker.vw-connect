.class public final synthetic Ln1/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ln1/a;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ln1/v;

.field public final synthetic g:Lk1/z0;

.field public final synthetic h:Lk1/i;

.field public final synthetic i:Lk1/g;

.field public final synthetic j:Lg1/j1;

.field public final synthetic k:Z

.field public final synthetic l:Le1/j;

.field public final synthetic m:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ln1/a;Lx2/s;Ln1/v;Lk1/z0;Lk1/i;Lk1/g;Lg1/j1;ZLe1/j;Lay0/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln1/e;->d:Ln1/a;

    .line 5
    .line 6
    iput-object p2, p0, Ln1/e;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Ln1/e;->f:Ln1/v;

    .line 9
    .line 10
    iput-object p4, p0, Ln1/e;->g:Lk1/z0;

    .line 11
    .line 12
    iput-object p5, p0, Ln1/e;->h:Lk1/i;

    .line 13
    .line 14
    iput-object p6, p0, Ln1/e;->i:Lk1/g;

    .line 15
    .line 16
    iput-object p7, p0, Ln1/e;->j:Lg1/j1;

    .line 17
    .line 18
    iput-boolean p8, p0, Ln1/e;->k:Z

    .line 19
    .line 20
    iput-object p9, p0, Ln1/e;->l:Le1/j;

    .line 21
    .line 22
    iput-object p10, p0, Ln1/e;->m:Lay0/k;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const p1, 0x1b0001

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v11

    .line 16
    iget-object v0, p0, Ln1/e;->d:Ln1/a;

    .line 17
    .line 18
    iget-object v1, p0, Ln1/e;->e:Lx2/s;

    .line 19
    .line 20
    iget-object v2, p0, Ln1/e;->f:Ln1/v;

    .line 21
    .line 22
    iget-object v3, p0, Ln1/e;->g:Lk1/z0;

    .line 23
    .line 24
    iget-object v4, p0, Ln1/e;->h:Lk1/i;

    .line 25
    .line 26
    iget-object v5, p0, Ln1/e;->i:Lk1/g;

    .line 27
    .line 28
    iget-object v6, p0, Ln1/e;->j:Lg1/j1;

    .line 29
    .line 30
    iget-boolean v7, p0, Ln1/e;->k:Z

    .line 31
    .line 32
    iget-object v8, p0, Ln1/e;->l:Le1/j;

    .line 33
    .line 34
    iget-object v9, p0, Ln1/e;->m:Lay0/k;

    .line 35
    .line 36
    invoke-static/range {v0 .. v11}, Ljp/q1;->a(Ln1/a;Lx2/s;Ln1/v;Lk1/z0;Lk1/i;Lk1/g;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;I)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0
.end method
