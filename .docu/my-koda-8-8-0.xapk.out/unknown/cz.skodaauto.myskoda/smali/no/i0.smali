.class public final Lno/i0;
.super Lno/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:Lno/e;


# direct methods
.method public constructor <init>(Lno/e;ILandroid/os/Bundle;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/i0;->g:Lno/e;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3}, Lno/w;-><init>(Lno/e;ILandroid/os/Bundle;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljo/b;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/i0;->g:Lno/e;

    .line 2
    .line 3
    iget-object p0, p0, Lno/e;->j:Lno/d;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lno/d;->d(Ljo/b;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final b()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lno/i0;->g:Lno/e;

    .line 2
    .line 3
    iget-object p0, p0, Lno/e;->j:Lno/d;

    .line 4
    .line 5
    sget-object v0, Ljo/b;->h:Ljo/b;

    .line 6
    .line 7
    invoke-interface {p0, v0}, Lno/d;->d(Ljo/b;)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0
.end method
