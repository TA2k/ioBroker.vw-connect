.class public final Law/s;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Law/w;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:Law/v;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Law/b;

.field public final synthetic m:Law/a;

.field public final synthetic n:Lay0/k;


# direct methods
.method public constructor <init>(Law/w;Lx2/s;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Law/s;->f:Law/w;

    .line 2
    .line 3
    iput-object p2, p0, Law/s;->g:Lx2/s;

    .line 4
    .line 5
    iput-boolean p3, p0, Law/s;->h:Z

    .line 6
    .line 7
    iput-object p4, p0, Law/s;->i:Law/v;

    .line 8
    .line 9
    iput-object p5, p0, Law/s;->j:Lay0/k;

    .line 10
    .line 11
    iput-object p6, p0, Law/s;->k:Lay0/k;

    .line 12
    .line 13
    iput-object p7, p0, Law/s;->l:Law/b;

    .line 14
    .line 15
    iput-object p8, p0, Law/s;->m:Law/a;

    .line 16
    .line 17
    iput-object p9, p0, Law/s;->n:Lay0/k;

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
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
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    const/16 p1, 0x6031

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v10

    .line 15
    iget-object v0, p0, Law/s;->f:Law/w;

    .line 16
    .line 17
    iget-object v1, p0, Law/s;->g:Lx2/s;

    .line 18
    .line 19
    iget-boolean v2, p0, Law/s;->h:Z

    .line 20
    .line 21
    iget-object v3, p0, Law/s;->i:Law/v;

    .line 22
    .line 23
    iget-object v4, p0, Law/s;->j:Lay0/k;

    .line 24
    .line 25
    iget-object v5, p0, Law/s;->k:Lay0/k;

    .line 26
    .line 27
    iget-object v6, p0, Law/s;->l:Law/b;

    .line 28
    .line 29
    iget-object v7, p0, Law/s;->m:Law/a;

    .line 30
    .line 31
    iget-object v8, p0, Law/s;->n:Lay0/k;

    .line 32
    .line 33
    invoke-static/range {v0 .. v10}, Ljp/m1;->b(Law/w;Lx2/s;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
