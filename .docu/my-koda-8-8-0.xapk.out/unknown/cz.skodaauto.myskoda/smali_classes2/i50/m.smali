.class public final synthetic Li50/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Lh50/w0;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Z

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(ZZZZZLh50/w0;Ljava/lang/String;ZI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Li50/m;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Li50/m;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Li50/m;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Li50/m;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Li50/m;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Li50/m;->i:Lh50/w0;

    .line 15
    .line 16
    iput-object p7, p0, Li50/m;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput-boolean p8, p0, Li50/m;->k:Z

    .line 19
    .line 20
    iput p9, p0, Li50/m;->l:I

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li50/m;->l:I

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
    iget-boolean v0, p0, Li50/m;->d:Z

    .line 18
    .line 19
    iget-boolean v1, p0, Li50/m;->e:Z

    .line 20
    .line 21
    iget-boolean v2, p0, Li50/m;->f:Z

    .line 22
    .line 23
    iget-boolean v3, p0, Li50/m;->g:Z

    .line 24
    .line 25
    iget-boolean v4, p0, Li50/m;->h:Z

    .line 26
    .line 27
    iget-object v5, p0, Li50/m;->i:Lh50/w0;

    .line 28
    .line 29
    iget-object v6, p0, Li50/m;->j:Ljava/lang/String;

    .line 30
    .line 31
    iget-boolean v7, p0, Li50/m;->k:Z

    .line 32
    .line 33
    invoke-static/range {v0 .. v9}, Li50/s;->k(ZZZZZLh50/w0;Ljava/lang/String;ZLl2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
