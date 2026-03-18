.class Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->setWebViewClient(Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

.field final synthetic val$paymentProvider:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->val$paymentProvider:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static synthetic a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->lambda$onError$4(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->lambda$onFormLoaded$3()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;Ljava/util/HashMap;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->lambda$onBeforeSubmit$2(Ljava/lang/String;Ljava/util/Map;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->lambda$postParams$0(Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic e(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->lambda$onValidElement$1(Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$onBeforeSubmit$2(Ljava/lang/String;Ljava/util/Map;)V
    .locals 1

    .line 1
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 7
    .line 8
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-interface {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onBeforeSubmit(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->a(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 22
    .line 23
    const/4 p2, 0x1

    .line 24
    invoke-static {p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->q(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Z)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 28
    .line 29
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->z(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method private synthetic lambda$onError$4(Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onError(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private synthetic lambda$onFormLoaded$3()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->y(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private synthetic lambda$onValidElement$1(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->m(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;->valueOf(Ljava/lang/String;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-static {p2}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    invoke-interface {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;->onValidateElement(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$FormElement;Z)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method private synthetic lambda$postParams$0(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-le v0, v1, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 11
    .line 12
    invoke-static {v0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->o(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 16
    .line 17
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->f(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    invoke-static {p1, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->p(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Z)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 30
    .line 31
    iget-object v0, p1, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 32
    .line 33
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p1, Ljava/lang/String;

    .line 42
    .line 43
    const-string v0, "Sepa"

    .line 44
    .line 45
    invoke-virtual {p2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    const-string p1, "BNKACCT"

    .line 52
    .line 53
    :cond_1
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 54
    .line 55
    invoke-static {p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 60
    .line 61
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->d(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 66
    .line 67
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->e(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-interface {p2, p1, v0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;->onSuccess(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 75
    .line 76
    const/4 p1, 0x0

    .line 77
    invoke-static {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->o(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    :cond_2
    return-void
.end method


# virtual methods
.method public androidLog(Ljava/lang/String;)V
    .locals 0
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-static {p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public continueValidationElement(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->continueValidationElement(Ljava/lang/String;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public formValidationError(Ljava/lang/String;)V
    .locals 0
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->t(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onBeforeSubmit(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
    .locals 18
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 4
    .line 5
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->g(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-nez v1, :cond_3

    .line 11
    .line 12
    iget-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 13
    .line 14
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    goto :goto_2

    .line 21
    :cond_0
    iget-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->val$paymentProvider:Ljava/lang/String;

    .line 22
    .line 23
    const-string v3, "Payon"

    .line 24
    .line 25
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    invoke-static/range {p1 .. p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->C(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move-object/from16 v1, p1

    .line 37
    .line 38
    :goto_0
    iget-object v3, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 39
    .line 40
    iget-object v3, v3, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->processingPayments:Ljava/util/Map;

    .line 41
    .line 42
    move-object/from16 v4, p2

    .line 43
    .line 44
    invoke-interface {v3, v4, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    new-instance v4, Lcom/google/gson/j;

    .line 48
    .line 49
    sget-object v5, Lcom/google/gson/internal/Excluder;->f:Lcom/google/gson/internal/Excluder;

    .line 50
    .line 51
    sget-object v6, Lcom/google/gson/j;->l:Lcom/google/gson/a;

    .line 52
    .line 53
    sget-object v7, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 54
    .line 55
    sget-object v9, Lcom/google/gson/j;->k:Lcom/google/gson/i;

    .line 56
    .line 57
    sget-object v12, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 58
    .line 59
    sget-object v15, Lcom/google/gson/j;->m:Lcom/google/gson/t;

    .line 60
    .line 61
    sget-object v16, Lcom/google/gson/j;->n:Lcom/google/gson/u;

    .line 62
    .line 63
    const/4 v8, 0x1

    .line 64
    const/4 v10, 0x1

    .line 65
    const/4 v11, 0x1

    .line 66
    move-object v13, v12

    .line 67
    move-object v14, v12

    .line 68
    move-object/from16 v17, v12

    .line 69
    .line 70
    invoke-direct/range {v4 .. v17}, Lcom/google/gson/j;-><init>(Lcom/google/gson/internal/Excluder;Lcom/google/gson/h;Ljava/util/Map;ZLcom/google/gson/i;ZILjava/util/List;Ljava/util/List;Ljava/util/List;Lcom/google/gson/x;Lcom/google/gson/x;Ljava/util/List;)V

    .line 71
    .line 72
    .line 73
    new-instance v3, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6$1;

    .line 74
    .line 75
    invoke-direct {v3, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6$1;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v3}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    invoke-static {v3}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    move-object/from16 v5, p3

    .line 87
    .line 88
    invoke-virtual {v4, v5, v3}, Lcom/google/gson/j;->b(Ljava/lang/String;Lcom/google/gson/reflect/TypeToken;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    check-cast v3, Ljava/util/Map;

    .line 93
    .line 94
    new-instance v4, Ljava/util/HashMap;

    .line 95
    .line 96
    invoke-direct {v4, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v4}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    :goto_1
    const/4 v5, 0x0

    .line 104
    invoke-interface {v3, v5}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v5

    .line 108
    if-eqz v5, :cond_2

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_2
    iget-object v3, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 112
    .line 113
    invoke-static {v3}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->t(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 114
    .line 115
    .line 116
    iget-object v3, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 117
    .line 118
    new-instance v5, Lcom/contoworks/kontocloud/uicomponents/widget/e;

    .line 119
    .line 120
    const/4 v6, 0x2

    .line 121
    invoke-direct {v5, v0, v1, v4, v6}, Lcom/contoworks/kontocloud/uicomponents/widget/e;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/io/Serializable;I)V

    .line 122
    .line 123
    .line 124
    const-wide/16 v0, 0x64

    .line 125
    .line 126
    invoke-virtual {v3, v5, v0, v1}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 127
    .line 128
    .line 129
    return v2

    .line 130
    :cond_3
    :goto_2
    iget-object v1, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 131
    .line 132
    invoke-static {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->g(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Z

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    if-eqz v1, :cond_4

    .line 137
    .line 138
    iget-object v0, v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 139
    .line 140
    invoke-static {v0, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->q(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Z)V

    .line 141
    .line 142
    .line 143
    :cond_4
    const/4 v0, 0x1

    .line 144
    return v0
.end method

.method public onError(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->t(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 7
    .line 8
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->l(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 15
    .line 16
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/b;

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    invoke-direct {v0, v1, p0, p2}, Lcom/contoworks/kontocloud/uicomponents/widget/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public onFormLoaded(Ljava/lang/String;)V
    .locals 2
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->s(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 7
    .line 8
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/d;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/d;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public onValidElement(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->m(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnValidationCallback;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    invoke-static {p2}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 16
    .line 17
    invoke-static {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->t(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 21
    .line 22
    new-instance v1, Lcom/contoworks/kontocloud/uicomponents/widget/f;

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    invoke-direct {v1, p0, p1, p2, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/f;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;Ljava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public postParams(Ljava/lang/String;)V
    .locals 4
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-le v0, v1, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 11
    .line 12
    invoke-static {v0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;->o(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->this$0:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm;

    .line 16
    .line 17
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;->val$paymentProvider:Ljava/lang/String;

    .line 18
    .line 19
    new-instance v2, Lcom/contoworks/kontocloud/uicomponents/widget/f;

    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-direct {v2, p0, p1, v1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/f;-><init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$6;Ljava/lang/String;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    return-void
.end method
