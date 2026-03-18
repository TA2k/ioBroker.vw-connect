.class public final synthetic Ln1/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ln1/v;

.field public final synthetic f:Ln1/c;

.field public final synthetic g:Lk1/z0;

.field public final synthetic h:Lg1/j1;

.field public final synthetic i:Z

.field public final synthetic j:Le1/j;

.field public final synthetic k:Lk1/i;

.field public final synthetic l:Lk1/g;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:I

.field public final synthetic o:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ln1/v;Ln1/c;Lk1/z0;Lg1/j1;ZLe1/j;Lk1/i;Lk1/g;Lay0/k;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln1/j;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Ln1/j;->e:Ln1/v;

    .line 7
    .line 8
    iput-object p3, p0, Ln1/j;->f:Ln1/c;

    .line 9
    .line 10
    iput-object p4, p0, Ln1/j;->g:Lk1/z0;

    .line 11
    .line 12
    iput-object p5, p0, Ln1/j;->h:Lg1/j1;

    .line 13
    .line 14
    iput-boolean p6, p0, Ln1/j;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Ln1/j;->j:Le1/j;

    .line 17
    .line 18
    iput-object p8, p0, Ln1/j;->k:Lk1/i;

    .line 19
    .line 20
    iput-object p9, p0, Ln1/j;->l:Lk1/g;

    .line 21
    .line 22
    iput-object p10, p0, Ln1/j;->m:Lay0/k;

    .line 23
    .line 24
    iput p11, p0, Ln1/j;->n:I

    .line 25
    .line 26
    iput p12, p0, Ln1/j;->o:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

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
    iget p1, p0, Ln1/j;->n:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v11

    .line 17
    iget p1, p0, Ln1/j;->o:I

    .line 18
    .line 19
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 20
    .line 21
    .line 22
    move-result v12

    .line 23
    iget-object v0, p0, Ln1/j;->d:Lx2/s;

    .line 24
    .line 25
    iget-object v1, p0, Ln1/j;->e:Ln1/v;

    .line 26
    .line 27
    iget-object v2, p0, Ln1/j;->f:Ln1/c;

    .line 28
    .line 29
    iget-object v3, p0, Ln1/j;->g:Lk1/z0;

    .line 30
    .line 31
    iget-object v4, p0, Ln1/j;->h:Lg1/j1;

    .line 32
    .line 33
    iget-boolean v5, p0, Ln1/j;->i:Z

    .line 34
    .line 35
    iget-object v6, p0, Ln1/j;->j:Le1/j;

    .line 36
    .line 37
    iget-object v7, p0, Ln1/j;->k:Lk1/i;

    .line 38
    .line 39
    iget-object v8, p0, Ln1/j;->l:Lk1/g;

    .line 40
    .line 41
    iget-object v9, p0, Ln1/j;->m:Lay0/k;

    .line 42
    .line 43
    invoke-static/range {v0 .. v12}, Ljp/r1;->a(Lx2/s;Ln1/v;Ln1/c;Lk1/z0;Lg1/j1;ZLe1/j;Lk1/i;Lk1/g;Lay0/k;Ll2/o;II)V

    .line 44
    .line 45
    .line 46
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0
.end method
