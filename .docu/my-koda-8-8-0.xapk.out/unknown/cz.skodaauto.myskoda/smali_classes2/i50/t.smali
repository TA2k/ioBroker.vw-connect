.class public final synthetic Li50/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx21/k;

.field public final synthetic e:Lh50/i0;

.field public final synthetic f:I

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Z

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lx21/k;Lh50/i0;IZZZZLay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li50/t;->d:Lx21/k;

    .line 5
    .line 6
    iput-object p2, p0, Li50/t;->e:Lh50/i0;

    .line 7
    .line 8
    iput p3, p0, Li50/t;->f:I

    .line 9
    .line 10
    iput-boolean p4, p0, Li50/t;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Li50/t;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Li50/t;->i:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Li50/t;->j:Z

    .line 17
    .line 18
    iput-object p8, p0, Li50/t;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Li50/t;->l:Lay0/a;

    .line 21
    .line 22
    iput p10, p0, Li50/t;->m:I

    .line 23
    .line 24
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
    iget p1, p0, Li50/t;->m:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v10

    .line 17
    iget-object v0, p0, Li50/t;->d:Lx21/k;

    .line 18
    .line 19
    iget-object v1, p0, Li50/t;->e:Lh50/i0;

    .line 20
    .line 21
    iget v2, p0, Li50/t;->f:I

    .line 22
    .line 23
    iget-boolean v3, p0, Li50/t;->g:Z

    .line 24
    .line 25
    iget-boolean v4, p0, Li50/t;->h:Z

    .line 26
    .line 27
    iget-boolean v5, p0, Li50/t;->i:Z

    .line 28
    .line 29
    iget-boolean v6, p0, Li50/t;->j:Z

    .line 30
    .line 31
    iget-object v7, p0, Li50/t;->k:Lay0/a;

    .line 32
    .line 33
    iget-object v8, p0, Li50/t;->l:Lay0/a;

    .line 34
    .line 35
    invoke-static/range {v0 .. v10}, Li50/z;->h(Lx21/k;Lh50/i0;IZZZZLay0/a;Lay0/a;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
