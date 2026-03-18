.class public final Lqu/b;
.super Landroid/os/AsyncTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lqu/c;


# direct methods
.method public constructor <init>(Lqu/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lqu/b;->a:Lqu/c;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/AsyncTask;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final doInBackground([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, [Ljava/lang/Float;

    .line 2
    .line 3
    iget-object p0, p0, Lqu/b;->a:Lqu/c;

    .line 4
    .line 5
    iget-object p0, p0, Lqu/c;->g:Lap0/o;

    .line 6
    .line 7
    invoke-virtual {p0}, Lap0/o;->M()V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    :try_start_0
    aget-object p1, p1, v0

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-interface {p0, p1}, Lru/a;->m(F)Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-virtual {p0}, Lap0/o;->X()V

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    invoke-virtual {p0}, Lap0/o;->X()V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public final onPostExecute(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Set;

    .line 2
    .line 3
    iget-object p0, p0, Lqu/b;->a:Lqu/c;

    .line 4
    .line 5
    iget-object p0, p0, Lqu/c;->h:Lsu/a;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Lsu/a;->a(Ljava/util/Set;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
