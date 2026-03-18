.class public final synthetic Lmc/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lmc/t;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lmc/t;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmc/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmc/b;->e:Lmc/t;

    .line 4
    .line 5
    iput-object p2, p0, Lmc/b;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lmc/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 7
    .line 8
    iget-object v0, p0, Lmc/b;->e:Lmc/t;

    .line 9
    .line 10
    iget-boolean v1, v0, Lmc/t;->c:Z

    .line 11
    .line 12
    iget-boolean v2, v0, Lmc/t;->d:Z

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->submit()V

    .line 17
    .line 18
    .line 19
    :cond_0
    if-eqz v2, :cond_1

    .line 20
    .line 21
    sget-object v1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->all:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    invoke-virtual {p1, v1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->setElementVisible(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;Z)V

    .line 25
    .line 26
    .line 27
    :cond_1
    iget-boolean p1, v0, Lmc/t;->c:Z

    .line 28
    .line 29
    if-nez p1, :cond_2

    .line 30
    .line 31
    if-eqz v2, :cond_3

    .line 32
    .line 33
    :cond_2
    sget-object p1, Lmc/g;->d:Lmc/g;

    .line 34
    .line 35
    iget-object p0, p0, Lmc/b;->f:Lay0/k;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_0
    check-cast p1, Landroid/content/Context;

    .line 44
    .line 45
    const-string v0, "it"

    .line 46
    .line 47
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    new-instance v0, Lmc/c;

    .line 51
    .line 52
    iget-object v1, p0, Lmc/b;->f:Lay0/k;

    .line 53
    .line 54
    invoke-direct {v0, v1}, Lmc/c;-><init>(Lay0/k;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lmc/b;->e:Lmc/t;

    .line 58
    .line 59
    iget-object v1, p0, Lmc/t;->i:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    const v2, 0x7f0d00e9

    .line 66
    .line 67
    .line 68
    const/4 v3, 0x0

    .line 69
    invoke-virtual {p1, v2, v3}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    const v2, 0x7f0a007d

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 81
    .line 82
    new-instance v2, Landroid/widget/FrameLayout$LayoutParams;

    .line 83
    .line 84
    const/4 v3, -0x1

    .line 85
    invoke-direct {v2, v3, v3}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, v2}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getOptions()Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-virtual {v2, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setPaymentProvider(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getOptions()Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    const/4 v2, 0x0

    .line 103
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    invoke-virtual {v1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setMode(Ljava/lang/Integer;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->setOnSubmitCallback(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getOptions()Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    iget-object v1, p0, Lmc/t;->g:Ljava/lang/String;

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setApiUrl(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->getOptions()Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    iget v1, p0, Lmc/t;->h:I

    .line 127
    .line 128
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-virtual {v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->setPaymentProviderMode(Ljava/lang/Integer;)V

    .line 133
    .line 134
    .line 135
    iget-object v0, p0, Lmc/t;->e:Ljava/util/List;

    .line 136
    .line 137
    check-cast v0, Ljava/util/Collection;

    .line 138
    .line 139
    new-array v1, v2, [Ljava/lang/String;

    .line 140
    .line 141
    invoke-interface {v0, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    check-cast v0, [Ljava/lang/String;

    .line 146
    .line 147
    iget-object p0, p0, Lmc/t;->f:Ljava/lang/String;

    .line 148
    .line 149
    invoke-virtual {p1, v0, p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->render([Ljava/lang/String;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    return-object p1

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
