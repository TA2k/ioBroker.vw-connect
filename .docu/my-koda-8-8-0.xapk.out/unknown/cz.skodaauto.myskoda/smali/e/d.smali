.class public final synthetic Le/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:Le/h;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Le/b;

.field public final synthetic g:Lf/a;


# direct methods
.method public synthetic constructor <init>(Le/h;Ljava/lang/String;Le/b;Lf/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le/d;->d:Le/h;

    .line 5
    .line 6
    iput-object p2, p0, Le/d;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Le/d;->f:Le/b;

    .line 9
    .line 10
    iput-object p4, p0, Le/d;->g:Lf/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 4

    .line 1
    iget-object p1, p0, Le/d;->d:Le/h;

    .line 2
    .line 3
    iget-object v0, p1, Le/h;->e:Ljava/util/LinkedHashMap;

    .line 4
    .line 5
    sget-object v1, Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;

    .line 6
    .line 7
    iget-object v2, p0, Le/d;->e:Ljava/lang/String;

    .line 8
    .line 9
    if-ne v1, p2, :cond_1

    .line 10
    .line 11
    iget-object p2, p1, Le/h;->g:Landroid/os/Bundle;

    .line 12
    .line 13
    iget-object p1, p1, Le/h;->f:Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    new-instance v1, Le/e;

    .line 16
    .line 17
    iget-object v3, p0, Le/d;->g:Lf/a;

    .line 18
    .line 19
    iget-object p0, p0, Le/d;->f:Le/b;

    .line 20
    .line 21
    invoke-direct {v1, v3, p0}, Le/e;-><init>(Lf/a;Le/b;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    invoke-interface {p1, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    invoke-virtual {p1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-interface {p1, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    invoke-interface {p0, v0}, Le/b;->a(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    :cond_0
    invoke-static {v2, p2}, Llp/wf;->a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Le/a;

    .line 48
    .line 49
    if-eqz p1, :cond_3

    .line 50
    .line 51
    invoke-virtual {p2, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget p2, p1, Le/a;->d:I

    .line 55
    .line 56
    iget-object p1, p1, Le/a;->e:Landroid/content/Intent;

    .line 57
    .line 58
    invoke-virtual {v3, p1, p2}, Lf/a;->c(Landroid/content/Intent;I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-interface {p0, p1}, Le/b;->a(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    sget-object p0, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 67
    .line 68
    if-ne p0, p2, :cond_2

    .line 69
    .line 70
    invoke-interface {v0, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :cond_2
    sget-object p0, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 75
    .line 76
    if-ne p0, p2, :cond_3

    .line 77
    .line 78
    invoke-virtual {p1, v2}, Le/h;->f(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    :cond_3
    return-void
.end method
