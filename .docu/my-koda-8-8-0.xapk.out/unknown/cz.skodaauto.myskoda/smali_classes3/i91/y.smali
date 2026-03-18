.class public final synthetic Li91/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/a;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/Integer;

.field public final synthetic h:Z

.field public final synthetic i:Le1/t;

.field public final synthetic j:Li91/h1;

.field public final synthetic k:Z

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lx2/s;Ljava/lang/String;Ljava/lang/Integer;ZLe1/t;Li91/h1;ZI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/y;->d:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Li91/y;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Li91/y;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Li91/y;->g:Ljava/lang/Integer;

    .line 11
    .line 12
    iput-boolean p5, p0, Li91/y;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Li91/y;->i:Le1/t;

    .line 15
    .line 16
    iput-object p7, p0, Li91/y;->j:Li91/h1;

    .line 17
    .line 18
    iput-boolean p8, p0, Li91/y;->k:Z

    .line 19
    .line 20
    iput p9, p0, Li91/y;->l:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li91/y;->l:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    iget-object v0, p0, Li91/y;->d:Lay0/a;

    .line 18
    .line 19
    iget-object v1, p0, Li91/y;->e:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Li91/y;->f:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v3, p0, Li91/y;->g:Ljava/lang/Integer;

    .line 24
    .line 25
    iget-boolean v4, p0, Li91/y;->h:Z

    .line 26
    .line 27
    iget-object v5, p0, Li91/y;->i:Le1/t;

    .line 28
    .line 29
    iget-object v6, p0, Li91/y;->j:Li91/h1;

    .line 30
    .line 31
    iget-boolean v7, p0, Li91/y;->k:Z

    .line 32
    .line 33
    invoke-static/range {v0 .. v9}, Li91/j0;->u(Lay0/a;Lx2/s;Ljava/lang/String;Ljava/lang/Integer;ZLe1/t;Li91/h1;ZLl2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
